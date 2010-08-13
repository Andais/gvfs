/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright (C) 2010 Ryan Brown
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Ryan Brown <r@nodr.org>
 */

/*
 * GVFS backend for Rackspace Cloud Files
 *
 * URI example: rack://user@auth.api.rackspacecloud.com/container/folder/object
 *
 * The password is the API key.
 */

#include <config.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <glib/gstdio.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include <gio/gunixinputstream.h>
#include <gio/gunixoutputstream.h>

#include "gvfsicon.h"

#include "gvfsbackendrack.h"
#include "gvfsjobopenforread.h"
#include "gvfsjobopeniconforread.h"
#include "gvfsjobmount.h"
#include "gvfsjobread.h"
#include "gvfsjobseekread.h"
#include "gvfsjobopenforwrite.h"
#include "gvfsjobwrite.h"
#include "gvfsjobclosewrite.h"
#include "gvfsjobseekwrite.h"
#include "gvfsjobsetdisplayname.h"
#include "gvfsjobqueryinfo.h"
#include "gvfsjobqueryinforead.h"
#include "gvfsjobqueryinfowrite.h"
#include "gvfsjobmove.h"
#include "gvfsjobdelete.h"
#include "gvfsjobqueryfsinfo.h"
#include "gvfsjobqueryattributes.h"
#include "gvfsjobenumerate.h"
#include "gvfsjobmakedirectory.h"
#include "gvfsdaemonprotocol.h"
#include "gvfskeyring.h"

#include <libsoup/soup.h>
#include <json-glib/json-glib.h>
#include "soup-input-stream.h"
#include "soup-output-stream.h"

#define RACK_ATTRIBUTE_CDN_ENABLED        "cdn::enabled"
#define RACK_ATTRIBUTE_CDN_URI            "cdn::uri"
#define RACK_ATTRIBUTE_CDN_TTL            "cdn::ttl"
#define RACK_ATTRIBUTE_CDN_LOG_RETENTION  "cdn::log-retention"
#define RACK_ATTRIBUTE_CDN_USER_AGENT_ACL "cdn::user-agent-acl"
#define RACK_ATTRIBUTE_CDN_REFERRER_ACL   "cdn::referrer-acl"

static GQuark id_q;

struct _GVfsBackendRack
{
  GVfsBackendHttp parent_instance;

  SoupURI *storage_uri;
  SoupURI *cdn_uri;
  gchar *user;
  gchar *api_key;
  const gchar *auth_token;
  gchar *host;
  int port;

  GPasswordSave password_save;

  gboolean user_specified;
  gboolean user_specified_in_uri;
  char *tmp_password;

};

G_DEFINE_TYPE (GVfsBackendRack, g_vfs_backend_rack, G_VFS_TYPE_BACKEND_HTTP)

static void
g_vfs_backend_rack_finalize (GObject *object)
{
  GVfsBackendRack *backend;

  backend = G_VFS_BACKEND_RACK (object);

  if (G_OBJECT_CLASS (g_vfs_backend_rack_parent_class)->finalize)
    (*G_OBJECT_CLASS (g_vfs_backend_rack_parent_class)->finalize) (object);
}

static void
g_vfs_backend_rack_init (GVfsBackendRack *backend)
{
  g_vfs_backend_set_user_visible (G_VFS_BACKEND (backend), TRUE);
}

typedef enum _FileType
{
  FILE_TYPE_ROOT,
  FILE_TYPE_CONTAINER,
  FILE_TYPE_OBJECT
} FileType;

typedef struct _RackPath
{
  char *container;
  char *folder;
  char *object;
} RackPath;

static RackPath* rack_path_new(const char *filename)
{
  RackPath *rack_path = g_new0(RackPath, 1);

  // special case for root
  if (!g_strcmp0(filename, "/"))
    {
      return rack_path;
    }
  char **split = g_strsplit(filename, "/", -1);

  // first = container
  // last = object
  // everything in between is folder

  GString *folder = g_string_new("");
  int i;
  for (i = 0; split[i] != NULL; i++)
    {
      char *current = split[i];
      char *encoded = soup_uri_encode(current, NULL);
      if (!g_strcmp0(current,""))
        {
          continue;
        }
      if (rack_path->container == NULL)
        {
          rack_path->container = encoded;
        }
      else if (split[i+1] == NULL)
        {
          rack_path->object = encoded;
        }
      else
        {
          if (folder->len != 0)
            {
              g_string_append_c(folder, '/');
            }
          g_string_append(folder, encoded);
	  g_free(encoded);
        }
    }
  g_strfreev(split);

  if (folder->len > 0)
    {
      rack_path->folder = folder->str;
    }
  g_string_free(folder, FALSE);

  return rack_path;
}

//free me!
static char*
rack_path_as_folder(RackPath *path)
{

  if (path->folder)
    {
      return g_strjoin("/", path->folder, path->object, NULL);
    }
  else
    {
      return g_strdup(path->object);
    }
}

//free me!
static char*
rack_path_as_object(RackPath *path)
{
  if (path->folder)
    {
      return g_strjoin("/", path->container, path->folder, path->object, NULL);
    }
  else
    {
      return g_strjoin("/", path->container, path->object, NULL);
    }
}


static void
rack_path_free(RackPath *path)
{
  if (path->container)
    {
      g_free(path->container);
    }
  if (path->folder)
    {
      g_free(path->folder);
    }
  if (path->object)
    {
      g_free(path->object);
    }

  g_free(path);
}


static FileType
rack_path_get_type(RackPath *path)
{
  if (path->container == NULL)
    {
      return FILE_TYPE_ROOT;
    }
  else if (path->object == NULL)
    {
      return FILE_TYPE_CONTAINER;
    }
  else
    {
      return FILE_TYPE_OBJECT;
    }
}

static SoupURI *
g_mount_spec_to_rack_auth_uri (GMountSpec *spec)
{
  SoupURI        *uri;
  const char     *port;
  const char     *host;
  gint            port_num;

  port = g_mount_spec_get (spec, "port");
  host = g_mount_spec_get (spec, "host");

  uri = soup_uri_new (NULL);

  soup_uri_set_scheme (uri, SOUP_URI_SCHEME_HTTPS);

  if (port && (port_num = atoi (port)))
    soup_uri_set_port (uri, port_num);

  soup_uri_set_host(uri, host);

  soup_uri_set_path (uri, "/v1.0");

  return uri;
}

static gboolean authenticate(GVfsBackendRack *rack,
                             const gchar *host,
                             const gchar *username, 
                             int port,
                             GMountSource *mount_source,
                             SoupMessage *auth_msg)
{
  gboolean res;
  gboolean aborted;
  gchar* new_username;
  gchar* new_password;
  gboolean obtained;

  obtained = FALSE;
  res = FALSE;
  new_username = NULL;
  new_password = NULL;

  if (g_vfs_keyring_is_available ())
    {
      obtained = g_vfs_keyring_lookup_password (username,
                 host,
                 NULL,
                 "rack",
                 "Cloud Files", //realm,
                 "basic",
                 port,
                 &new_username,
                 NULL,
                 &new_password);
    }

  // No info in the keyring, so ask the user interactively
  if (!obtained)
    {
      GAskPasswordFlags pass_flags;
      gchar *prompt;

      pass_flags = G_ASK_PASSWORD_NEED_PASSWORD;
      if (!username)
        {
          pass_flags |= G_ASK_PASSWORD_NEED_USERNAME;
        }
      if (g_vfs_keyring_is_available())
        {
          pass_flags |= G_ASK_PASSWORD_SAVING_SUPPORTED;
        }

      prompt = g_strdup("Enter password for Cloud Files: ");

      res = g_mount_source_ask_password (mount_source,
                                         prompt,
                                         username,
                                         NULL,
                                         pass_flags,
                                         &aborted,
                                         &new_password,
                                         &new_username,
                                         NULL,
                                         NULL,
                                         &rack->password_save);
      obtained = res && (!aborted);
      g_free(prompt);
    }

  if (obtained)
    {
      if (username)
        {
          rack->user = g_strdup(username);
        }
      else
        {
          rack->user = g_strdup(new_username);
        }
      rack->api_key = g_strdup(new_password);
    }

  return obtained;
}

static void save_auth(GVfsBackendRack *rack,
                      const gchar *host,
                      int port)
{

  g_vfs_keyring_save_password(rack->user,
                              host,
                              NULL,
                              "rack",
                              "Cloud Files",
                              "basic",
                              port,
                              rack->api_key,
                              rack->password_save);
}


static void
do_mount (GVfsBackend  *backend,
          GVfsJobMount *job,
          GMountSpec   *mount_spec,
          GMountSource *mount_source,
          gboolean      is_automount)
{

  GVfsBackendRack *rack;
  const char *host;
  const char *user;
  int port;
  SoupURI *auth_uri;
  SoupSession *session;
  SoupMessage *auth_msg;
  SoupMessageHeaders *auth_msg_headers;
  guint auth_return;
  gboolean auth_success;

  G_VFS_BACKEND_RACK(backend)->password_save = G_PASSWORD_SAVE_NEVER;

  rack = G_VFS_BACKEND_RACK(backend);
  user = g_mount_spec_get (mount_spec, "user");

  auth_uri = g_mount_spec_to_rack_auth_uri(mount_spec);
  port = auth_uri->port;
  host = auth_uri->host;
  g_print("host: %s\n", host);

  session = G_VFS_BACKEND_HTTP(backend)->session;

  auth_msg = soup_message_new_from_uri(SOUP_METHOD_GET, auth_uri);
  auth_msg_headers = auth_msg->request_headers;

  if (!authenticate(rack, host, user, port, mount_source, auth_msg))
    {
      /*g_set_error_literal (error, G_IO_ERROR,
                           aborted ? G_IO_ERROR_FAILED_HANDLED : G_IO_ERROR_PERMISSION_DENIED,
                           _("Password dialog cancelled"));*/

      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("Authentication cancelled"));
      return;
    }

  if (!rack->user || !rack->api_key)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("Need username and password"));
      return;
    }
  soup_message_headers_append(auth_msg_headers, "X-Auth-User", rack->user);
  soup_message_headers_append(auth_msg_headers, "X-Auth-Key", rack->api_key);
  auth_return = http_backend_send_message(backend, auth_msg);
  auth_success = SOUP_STATUS_IS_SUCCESSFUL(auth_return);

  if (!auth_success)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), auth_msg->reason_phrase);
      return;
    }

  if (auth_return == SOUP_STATUS_NO_CONTENT)
    {
      // auth was successful
      GVfsBackendRack* rack = G_VFS_BACKEND_RACK(backend);
      const gchar *storage_uri_value;
      storage_uri_value = soup_message_headers_get_one(auth_msg->response_headers, "X-Storage-Url");
      SoupURI *storage_uri;
      storage_uri = soup_uri_new(storage_uri_value);
      rack->storage_uri = storage_uri;

      const gchar *cdn_uri_value = soup_message_headers_get_one(auth_msg->response_headers, "X-CDN-Management-Url");
      SoupURI *cdn_uri = soup_uri_new(cdn_uri_value);
      rack->cdn_uri = cdn_uri;

      const gchar *auth_token = soup_message_headers_get_one(auth_msg->response_headers, "X-Auth-Token");
      rack->auth_token = auth_token;
      g_print("AUTH TOKEN: %s\n",auth_token);

      save_auth(rack, host, port);

    }
  else
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("Authentication failed"));
      return;
    }

  const gchar *display_name = g_strdup_printf("Cloud Files on %s", host);
  g_vfs_backend_set_display_name(backend, display_name);
  g_vfs_backend_set_mount_spec (backend, mount_spec);
  g_vfs_backend_set_icon_name (backend, "folder-remote");

  g_vfs_job_succeeded(G_VFS_JOB(job));
}

static gboolean
try_unmount (GVfsBackend    *backend,
             GVfsJobUnmount *job,
             GMountUnmountFlags flags,
             GMountSource *mount_source)
{
  _exit (0);
}

static GHashTable* 
query_new() 
{
  return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

static void 
query_set_json(GHashTable *params) 
{
  g_hash_table_insert(params, g_strdup("format"), g_strdup("json"));
}

static void 
query_set_path(GHashTable *params, const char* path) 
{
  g_hash_table_insert(params, g_strdup("path"), g_strdup(path));
}

static SoupMessage*
new_cloud_message(GVfsBackendRack *rack, const gchar *http_method, const gchar *custom_path, GHashTable *query)
{

  // The storage uri is the base content server
  SoupURI *uri = soup_uri_copy(rack->storage_uri);
  gchar *base_path = uri->path;
  gchar *full_path = g_strconcat(base_path, "/", custom_path, NULL);

  soup_uri_set_path(uri, full_path);
  g_free(full_path);

  if (query)
    {
      char *encoded_query = soup_form_encode_hash(query);
      soup_uri_set_query(uri, encoded_query);
      g_free(encoded_query);
    }

  // Authenticate the message
  SoupMessage *msg = soup_message_new_from_uri(http_method, uri);
  soup_message_headers_append(msg->request_headers, "X-Auth-Token", rack->auth_token);

  return msg;
}

static SoupMessage*
new_container_cdn_message(GVfsBackendRack *rack, RackPath *path, const gchar* method) 
{
  SoupURI *uri = soup_uri_copy(rack->cdn_uri);

  gchar *base_path = uri->path;
  gchar *full_path = g_strconcat(base_path, "/", path->container, NULL);

  soup_uri_set_path(uri, full_path);
  g_free(full_path);

  SoupMessage *msg = soup_message_new_from_uri(method, uri);
  soup_message_headers_append(msg->request_headers, "X-Auth-Token", rack->auth_token);
  
  g_print("container cdn uri: %s\n", soup_uri_to_string(soup_message_get_uri(msg), FALSE));

  return msg;
}

static SoupMessage*
new_object_message(GVfsBackendRack *rack, RackPath *path, const char *method)
{
  char *object = rack_path_as_object(path);
  SoupMessage *msg = new_cloud_message(rack, method, object, NULL);
  g_free(object);

  g_print("object %s uri: %s\n", method, soup_uri_to_string(soup_message_get_uri(msg), FALSE));
  return msg;
}

static SoupMessage*
new_object_message_from_uri(GVfsBackendRack *rack, SoupURI *uri, const char *method)
{
  SoupMessage *msg = new_cloud_message(rack, method, NULL, NULL);
  soup_message_set_uri(msg, uri);
  return msg;
}

static SoupMessage*
new_folder_put_message(GVfsBackendRack *rack, RackPath *path)
{
  char *object = rack_path_as_object(path);
  SoupMessage *msg = new_cloud_message(rack, SOUP_METHOD_PUT, object, NULL);
  g_free(object);

  soup_message_headers_set_content_length(msg->request_headers, 0);
  soup_message_headers_set_content_type(msg->request_headers, "application/directory", NULL);

  g_print("folder put uri: %s\n", soup_uri_to_string(soup_message_get_uri(msg), FALSE));
  return msg;
}

static SoupMessage*
new_root_list_message(GVfsBackendRack *rack)
{
  GHashTable *query = query_new();
  query_set_json(query);
  SoupMessage *msg = new_cloud_message(rack, SOUP_METHOD_GET, NULL, query);
  g_hash_table_unref(query);
  g_print("container list uri: %s\n", soup_uri_to_string(soup_message_get_uri(msg), FALSE));

  return msg;
}

static SoupMessage*
new_create_container_message(GVfsBackendRack *rack, RackPath *path)
{
  SoupMessage *msg = new_cloud_message(rack, SOUP_METHOD_PUT, path->container, NULL);
  g_print("mkcontainer uri: %s\n", soup_uri_to_string(soup_message_get_uri(msg), FALSE));

  return msg;
}

static SoupMessage*
new_delete_container_message(GVfsBackendRack *rack, RackPath *path)
{
  SoupMessage *msg = new_cloud_message(rack, SOUP_METHOD_DELETE, path->container, NULL);
  g_print("rmcontainer uri: %s\n", soup_uri_to_string(soup_message_get_uri(msg), FALSE));

  return msg;
}

static SoupMessage*
new_head_container_message(GVfsBackendRack *rack, RackPath *path)
{
  SoupMessage *msg = new_cloud_message(rack, SOUP_METHOD_HEAD, path->container, NULL);
  g_print("headcontainer uri: %s\n", soup_uri_to_string(soup_message_get_uri(msg), FALSE));

  return msg;
}


static SoupMessage*
new_container_list_message(GVfsBackendRack *rack, RackPath *path)
{
  GHashTable *query = query_new();
  query_set_json(query);
  SoupMessage *msg = new_cloud_message(rack, SOUP_METHOD_GET, path->container, query);
  g_hash_table_unref(query);
  g_print("object list uri: %s\n", soup_uri_to_string(soup_message_get_uri(msg), FALSE));
  return msg;
}

static SoupMessage*
new_folder_list_message(GVfsBackendRack *rack, RackPath *path, gboolean json)
{

  char *folder = rack_path_as_folder(path);
  char *decoded_folder = soup_uri_decode(folder);
  g_free(folder);

  GHashTable *query = query_new();
  query_set_path(query, decoded_folder); 
  g_free(decoded_folder);

  if (json)
    {
      query_set_json(query);
    }

  SoupMessage *msg = new_cloud_message(rack, SOUP_METHOD_GET, path->container, query);
  g_hash_table_unref(query);
  return msg;
}

// TODO return GERROR?
static gboolean enumerate_root(GVfsBackendRack *rack,
                               GVfsJobEnumerate *job,
                               const char *data,
                               gsize len)
{

  JsonParser *parser = json_parser_new();
  gboolean ret;
  GIcon *icon;

  GError *err = NULL;
  ret = json_parser_load_from_data(parser, data, len, &err);
  if (!ret)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("Unable to parse JSON response: %s"), err->message);
      g_error_free(err);
      return FALSE;
    }

  JsonNode *root = json_parser_get_root(parser);
  JsonArray *array = json_node_get_array(root);

  GList *containers = json_array_get_elements(array);
  GList *iter = containers;
  while (iter)
    {
      JsonNode *container_node = (JsonNode*) iter->data;
      JsonObject *container = json_node_get_object(container_node);

      const gchar *name = g_strdup(json_object_get_string_member(container, "name"));

      GFileInfo *info = g_file_info_new();
      g_file_info_set_name(info, name);
      g_file_info_set_edit_name(info, name);
      g_file_info_set_display_name(info, name);
      g_file_info_set_file_type(info, G_FILE_TYPE_DIRECTORY);
      g_file_info_set_content_type(info, "inode/directory");
      g_file_info_set_attribute_uint64 (info,
                                        G_FILE_ATTRIBUTE_TIME_CREATED,
                                        0);

      icon = g_themed_icon_new("folder");
      g_file_info_set_icon(info, icon);
      g_object_unref(icon);

      g_vfs_job_enumerate_add_info(job, info);

      iter = g_list_next(iter);
    }

  g_list_free(containers);
  g_object_unref(parser);

  return TRUE;
}

static guint64
iso_8601_to_unix(const gchar* iso)
{
  GTimeVal time_val;
  if (!g_time_val_from_iso8601(iso, &time_val))
    {
      return -1;
    }

  return time_val.tv_sec;
}

static void
content_type_to_file_info(const char* content_type,
                          const char* filename,
                          GFileInfo *info)
{
  GIcon *icon;
  if (!g_strcmp0("application/directory", content_type))
    {
      // This is a folder marker object
      g_file_info_set_file_type(info, G_FILE_TYPE_DIRECTORY);
      g_file_info_set_content_type(info, "inode/directory");
      GIcon *icon = g_themed_icon_new("folder");
      g_file_info_set_icon(info, icon);
      g_object_unref(icon);
    }
  else
    {
      g_file_info_set_file_type(info, G_FILE_TYPE_REGULAR);

      if (content_type == NULL)
        content_type = g_content_type_guess (filename, NULL, 0, NULL);

      icon = g_content_type_get_icon (content_type);

      if (G_IS_THEMED_ICON (icon))
        g_themed_icon_append_name (G_THEMED_ICON (icon), "text-x-generic");

      g_file_info_set_icon(info, icon);
      g_object_unref(icon);

      g_file_info_set_content_type (info, content_type);
    }
}

static void
json_to_file_info(JsonObject *object,
                  GFileInfo *info)
{

  const gchar *name = json_object_get_string_member(object, "name");
  const gchar *type = json_object_get_string_member(object, "content_type");
  const gchar *modified = json_object_get_string_member(object, "last_modified");
  gint64 bytes = json_object_get_int_member(object, "bytes");

  g_file_info_set_name(info, name);
  g_file_info_set_edit_name(info, name);
  g_file_info_set_display_name(info, name);

  content_type_to_file_info(type, name, info);
  g_file_info_set_size(info, bytes);

  guint64 modified_time = iso_8601_to_unix(modified);
  g_file_info_set_attribute_uint64 (info,
                                    G_FILE_ATTRIBUTE_TIME_MODIFIED,
                                    modified_time);

}

static gboolean enumerate_container(GVfsBackendRack *rack,
                                    GVfsJobEnumerate *job,
                                    const char *data,
                                    gsize len)
{

  JsonParser *parser = json_parser_new();
  gboolean ret;
  GError *err = NULL;
  ret = json_parser_load_from_data(parser, data, len, &err);
  if (!ret)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("Unable to parse JSON response: %s"), err->message);
      g_error_free(err);
      return FALSE;
    }

  JsonNode *root = json_parser_get_root(parser);
  JsonArray *array = json_node_get_array(root);

  GList *objects = json_array_get_elements(array);
  GList *iter = objects;
  while (iter)
    {
      JsonNode *object_node = (JsonNode*) iter->data;
      JsonObject *object = json_node_get_object(object_node);

      GFileInfo *info = g_file_info_new();

      const gchar *name = json_object_get_string_member(object, "name");
      if (!g_strrstr(name, "/"))
        {
          json_to_file_info(object, info);

          g_vfs_job_enumerate_add_info(job, info);
        }

      iter = g_list_next(iter);
    }

  g_list_free(objects);
  g_object_unref(parser);

  return TRUE;
}

static gboolean enumerate_folder(GVfsBackendRack *rack,
                                 GVfsJobEnumerate *job,
                                 RackPath *path,
                                 const char *data,
                                 gsize len)
{
  char *encoded_folder = rack_path_as_folder(path);
  char *folder = soup_uri_decode(encoded_folder);
  g_free(encoded_folder);
  gsize folder_len = strlen(folder);
  JsonParser *parser = json_parser_new();
  gboolean ret;

  GError *err = NULL;
  ret = json_parser_load_from_data(parser, data, len, &err);
  if (!ret)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("Unable to parse JSON response: %s"), err->message);
      g_error_free(err);
      g_free(folder);
      return FALSE;
    }

  JsonNode *root = json_parser_get_root(parser);
  JsonArray *array = json_node_get_array(root);

  GList *objects = json_array_get_elements(array);
  GList *iter = objects;
  while (iter)
    {
      JsonNode *object_node = (JsonNode*) iter->data;
      JsonObject *object = json_node_get_object(object_node);

      GFileInfo *info = g_file_info_new();

      const gchar *name = json_object_get_string_member(object, "name");
      g_print("[folder_enumerate] name: %s\n", name);
      if (strlen(name) > folder_len)
        {
          name += folder_len + 1;
          if (name)
            {
              json_to_file_info(object, info);
              g_file_info_set_name(info, name);
              g_file_info_set_display_name(info, name);
              g_file_info_set_edit_name(info, name);
              g_vfs_job_enumerate_add_info(job, info);
            }
        }

      iter = g_list_next(iter);
    }

  g_list_free(objects);
  g_object_unref(parser);
  g_free(folder);

  return TRUE;
}

static void
do_enumerate (GVfsBackend           *backend,
              GVfsJobEnumerate      *job,
              const char            *filename,
              GFileAttributeMatcher *matcher,
              GFileQueryInfoFlags    flags)
{

  SoupMessage *msg;
  guint ret;
  RackPath *path;
  FileType type;

  path = rack_path_new(filename);
  type = rack_path_get_type(path);

  switch (type)
    {
    case FILE_TYPE_ROOT:
      msg = new_root_list_message(G_VFS_BACKEND_RACK(backend));
      break;
    case FILE_TYPE_CONTAINER:
      msg = new_container_list_message(G_VFS_BACKEND_RACK(backend), path);
      break;
    case FILE_TYPE_OBJECT:
      msg = new_folder_list_message(G_VFS_BACKEND_RACK(backend), path, TRUE);
      break;
    default:
      g_assert_not_reached();
    }

  ret = http_backend_send_message(backend, msg);

  if (ret != SOUP_STATUS_OK)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
      g_object_unref(msg);
      rack_path_free(path);
      return;
    }

  switch (type)
    {
    case FILE_TYPE_ROOT:
      ret = enumerate_root(G_VFS_BACKEND_RACK(backend), job, msg->response_body->data, msg->response_body->length);
      break;
    case FILE_TYPE_CONTAINER:
      ret = enumerate_container(G_VFS_BACKEND_RACK(backend), job, msg->response_body->data, msg->response_body->length);
      break;
    case FILE_TYPE_OBJECT:
      ret = enumerate_folder(G_VFS_BACKEND_RACK(backend), job, path, msg->response_body->data, msg->response_body->length);
      break;
    default:
      g_assert_not_reached();
    }

  g_object_unref(msg);
  rack_path_free(path);

  g_vfs_job_succeeded(G_VFS_JOB(job));
  g_vfs_job_enumerate_done(G_VFS_JOB_ENUMERATE(job));
}

static void date_header_to_file_info(SoupMessage *msg, GFileInfo *info)
{

  const char *date_header = soup_message_headers_get_one(msg->response_headers, "Last-Modified");
  if (date_header)
    {
      SoupDate *date = soup_date_new_from_string(date_header);
      if (date)
        {
          g_file_info_set_attribute_uint64 (info,
                                            G_FILE_ATTRIBUTE_TIME_MODIFIED,
                                            soup_date_to_time_t(date));
        }
    }

}

static void
query_container_cdn(GVfsBackend *backend,
                GVfsJobQueryInfo *job,
                GFileInfo *info,
                RackPath *path,
		GFileAttributeMatcher *matcher)
{
  SoupMessage *msg;
  guint ret;
  const char *cdn_enabled_header;
  const char *cdn_uri_header;
  const char *ttl_header;
  const char *log_header;
  const char *user_agent;
  const char *referrer;

  msg = new_container_cdn_message(G_VFS_BACKEND_RACK(backend), path, SOUP_METHOD_HEAD);
  ret = http_backend_send_message(G_VFS_BACKEND(backend), msg);

  switch(ret) 
    {
    case SOUP_STATUS_NO_CONTENT:

      cdn_enabled_header = soup_message_headers_get_one(msg->response_headers, "X-CDN-Enabled");
      if(cdn_enabled_header) 
      {
	gboolean cdn_enabled = !g_strcmp0(cdn_enabled_header, "True");
	g_file_info_set_attribute_boolean(info, RACK_ATTRIBUTE_CDN_ENABLED, cdn_enabled);
      }

      cdn_uri_header = soup_message_headers_get_one(msg->response_headers, "X-CDN-URI");
      if(cdn_uri_header)
      {
	g_file_info_set_attribute_string(info, RACK_ATTRIBUTE_CDN_URI, cdn_uri_header);
      }

      ttl_header = soup_message_headers_get_one(msg->response_headers, "X-TTL");
      if(ttl_header)
      {
	guint32 val = (guint32) g_ascii_strtoll(ttl_header, NULL, 10);
	g_file_info_set_attribute_uint32(info, RACK_ATTRIBUTE_CDN_TTL, val);
      }

      log_header = soup_message_headers_get_one(msg->response_headers, "X-Log-Retention");
      if(log_header)
      {
	gboolean retention = !g_strcmp0(log_header, "True");
	g_file_info_set_attribute_boolean(info, RACK_ATTRIBUTE_CDN_LOG_RETENTION, retention);
      }

      user_agent = soup_message_headers_get_one(msg->response_headers, "X-User-Agent-ACL");
      if(user_agent)
      {
	g_file_info_set_attribute_string(info, RACK_ATTRIBUTE_CDN_USER_AGENT_ACL, user_agent);
      }

      referrer = soup_message_headers_get_one(msg->response_headers, "X-Referrer-ACL");
      if(referrer)
      {
	g_file_info_set_attribute_string(info, RACK_ATTRIBUTE_CDN_REFERRER_ACL, referrer);
      }

      g_vfs_job_succeeded(G_VFS_JOB(job));
      break;
    case SOUP_STATUS_NOT_FOUND:
      g_file_info_set_attribute_boolean(info, RACK_ATTRIBUTE_CDN_ENABLED, FALSE);
      g_vfs_job_succeeded(G_VFS_JOB(job));
      break;
    default:
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
    }

    g_object_unref(msg);
}

static void
query_container(GVfsBackend *backend,
                GVfsJobQueryInfo *job,
                GFileInfo *info,
                RackPath *path,
		GFileAttributeMatcher *matcher)
{
  SoupMessage *msg;
  guint ret;


  msg = new_head_container_message(G_VFS_BACKEND_RACK(backend), path);
  ret = http_backend_send_message(G_VFS_BACKEND(backend), msg);

  switch(ret) 
    {
    case SOUP_STATUS_NO_CONTENT:
      g_file_info_set_file_type(info, G_FILE_TYPE_DIRECTORY);
      content_type_to_file_info("application/directory", path->container, info);
      char *decoded = soup_uri_decode(path->container);
      g_file_info_set_name(info, decoded);
      g_free(decoded);
      
      if(g_file_attribute_matcher_matches(matcher, "cdn::*"))
      {
	query_container_cdn(backend, job, info, path, matcher);
      }
      else
      {
	g_vfs_job_succeeded(G_VFS_JOB(job));
      }

      break;
    case SOUP_STATUS_NOT_FOUND:
      g_vfs_job_failed (G_VFS_JOB (job), G_IO_ERROR, G_IO_ERROR_NOT_FOUND,_("Container not found"));
      break;
    default:
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
    }

  g_object_unref(msg);
}

static void
query_object(GVfsBackend *backend,
             GVfsJobQueryInfo *job,
             GFileInfo *info,
             RackPath *path)
{
  SoupMessage *msg;
  guint ret;
  const char *content_type;
  goffset content_length;

  msg = new_object_message(G_VFS_BACKEND_RACK(backend), path, SOUP_METHOD_HEAD);
  char *decoded = soup_uri_decode(path->object);
  g_file_info_set_name(info, decoded);
  g_free(decoded);
  ret = http_backend_send_message(backend, msg);
  if (ret == SOUP_STATUS_NOT_FOUND)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_NOT_FOUND, _("Not Found"));
    }
  else if (!SOUP_STATUS_IS_SUCCESSFUL(ret))
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
    }
  else
    {

      date_header_to_file_info(msg, info);
      content_type = soup_message_headers_get_content_type(msg->response_headers, NULL);
      if (content_type)
        {
          content_type_to_file_info(content_type, path->object, info);
        }

      content_length = soup_message_headers_get_content_length(msg->response_headers);
      g_file_info_set_size(info, content_length);
      g_vfs_job_succeeded(G_VFS_JOB(job));
    }

  g_object_unref(msg);

}

static void
do_query_info (GVfsBackend           *backend,
               GVfsJobQueryInfo      *job,
               const char            *filename,
               GFileQueryInfoFlags    flags,
               GFileInfo             *info,
               GFileAttributeMatcher *matcher)
{

  g_print("rack:do_query_info filename: %s\n", filename);
  RackPath *path = rack_path_new(filename);
  FileType type = rack_path_get_type(path);

  switch (type)
    {
    case FILE_TYPE_ROOT:
      // don't really have any info for the root
      g_print("[do_query_info] FILE_TYPE_ROOT\n");
      g_file_info_set_file_type(info, G_FILE_TYPE_DIRECTORY);
      g_file_info_set_display_name(info, "/");

      g_vfs_job_succeeded(G_VFS_JOB(job));

      break;
    case FILE_TYPE_CONTAINER:
      query_container(backend, job, info, path, matcher);
      break;
    case FILE_TYPE_OBJECT:
      query_object(backend, job, info, path);
      break;
    default:
      g_assert_not_reached();
    }

  rack_path_free(path);
}

static void
make_container(GVfsBackend *backend,
               GVfsJobMakeDirectory *job,
               RackPath *path)
{
  SoupMessage *msg;
  guint ret;

  msg = new_create_container_message(G_VFS_BACKEND_RACK(backend), path);
  ret = http_backend_send_message(backend, msg);
  if (ret == SOUP_STATUS_CREATED)
    {
      g_vfs_job_succeeded(G_VFS_JOB(job));
    }
  else if (ret == SOUP_STATUS_ACCEPTED)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_EXISTS, _("Container exists"));
    }
  else
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
    }

}

static void
make_folder(GVfsBackend *backend,
            GVfsJobMakeDirectory *job,
            RackPath *path)
{
  SoupMessage *msg;
  guint ret;

  msg = new_folder_put_message(G_VFS_BACKEND_RACK(backend), path);
  ret = http_backend_send_message(backend, msg);
  if (ret == SOUP_STATUS_CREATED)
    {
      g_vfs_job_succeeded(G_VFS_JOB(job));
    }
  else
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
    }

  g_object_unref(msg);
}

static void
do_make_directory (GVfsBackend          *backend,
                   GVfsJobMakeDirectory *job,
                   const char           *filename)
{

  RackPath *path = rack_path_new(filename);
  FileType type = rack_path_get_type(path);

  switch (type)
    {
    case FILE_TYPE_ROOT:
      g_assert_not_reached();
      break;
    case FILE_TYPE_CONTAINER:
      make_container(backend, job, path);
      break;
    case FILE_TYPE_OBJECT:
      make_folder(backend, job, path);
      break;
    }

  rack_path_free(path);
}

static gboolean
is_folder_empty(GVfsBackendRack *rack,
                RackPath *path)
{

  // TODO no way for this to fail
  SoupMessage *msg = new_folder_list_message(rack, path, FALSE);
  http_backend_send_message(G_VFS_BACKEND(rack), msg);
  gboolean empty = msg->response_body->length == 0;
  g_object_unref(msg);
  return empty;
}

static void
delete_container(GVfsBackend *backend,
                 GVfsJobDelete *job,
                 RackPath *path)
{
  SoupMessage *msg;
  guint ret;

  msg = new_delete_container_message(G_VFS_BACKEND_RACK(backend), path);
  ret = http_backend_send_message(backend, msg);
  if (ret == SOUP_STATUS_NO_CONTENT)
    {
      g_vfs_job_succeeded(G_VFS_JOB(job));
    }
  else if (ret == SOUP_STATUS_NOT_FOUND)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_NOT_FOUND, _("Not found"));
    }
  else if (ret == SOUP_STATUS_CONFLICT)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_NOT_EMPTY, _("Not empty"));
    }

  g_object_unref(msg);
}

static void
delete_object(GVfsBackend *backend,
              GVfsJobDelete *job,
              RackPath *path)
{
  SoupMessage *msg;
  gboolean empty;
  guint ret;

  // two round trips to delete an object- can this be done better?
  empty = is_folder_empty(G_VFS_BACKEND_RACK(backend), path);
  if (empty)
    {
      msg = new_object_message(G_VFS_BACKEND_RACK(backend), path, SOUP_METHOD_DELETE);
      ret = http_backend_send_message(backend, msg);
      if (ret == SOUP_STATUS_NOT_FOUND)
        {
          g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_NOT_FOUND, _("Not found"));
        }
      else if (ret != SOUP_STATUS_NO_CONTENT)
        {
          g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
        }
      else
        {
          g_vfs_job_succeeded(G_VFS_JOB(job));
        }
    }
  else
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_NOT_EMPTY, _("Not empty"));
    }

  g_object_unref(msg);
}

static void
do_delete (GVfsBackend   *backend,
           GVfsJobDelete *job,
           const char    *filename)
{
  RackPath *path;
  FileType type;

  path = rack_path_new(filename);
  type = rack_path_get_type(path);

  switch (type)
    {
    case FILE_TYPE_ROOT:
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED, _("Cannot delete root"));
      rack_path_free(path);
      return;
    case FILE_TYPE_CONTAINER:
      delete_container(backend, job, path);
      break;
    case FILE_TYPE_OBJECT:
      delete_object(backend, job, path);
      break;
    }

  rack_path_free(path);
}

static void
open_for_read_ready (GObject      *source_object,
                     GAsyncResult *result,
                     gpointer      user_data)
{
  GInputStream *stream;
  GVfsJob      *job;
  gboolean      res;
  gboolean      can_seek;
  GError       *error;

  stream = G_INPUT_STREAM (source_object);
  error  = NULL;
  job    = G_VFS_JOB (user_data);

  res = soup_input_stream_send_finish (stream,
                                       result,
                                       &error);
  if (res == FALSE)
    {
      g_vfs_job_failed_literal (G_VFS_JOB (job),
                                error->domain,
                                error->code,
                                error->message);

      g_error_free (error);
      g_object_unref (stream);
      return;
    }

  can_seek = G_IS_SEEKABLE (stream) && g_seekable_can_seek (G_SEEKABLE (stream));

  g_vfs_job_open_for_read_set_can_seek (G_VFS_JOB_OPEN_FOR_READ (job), can_seek);
  g_vfs_job_open_for_read_set_handle (G_VFS_JOB_OPEN_FOR_READ (job), stream);
  g_vfs_job_succeeded (job);
}

static void
try_tested_object (SoupSession *session, SoupMessage *head_msg,
                   gpointer user_data)
{
  GInputStream    *stream;
  SoupMessage     *get_msg;
  GVfsJob *job = G_VFS_JOB (user_data);
  GVfsBackendHttp *op_backend = job->backend_data;

  const char *content_type = soup_message_headers_get_one(head_msg->response_headers, "Content-Type");
  if(!g_strcmp0(content_type, "application/directory"))
  {
    g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_IS_DIRECTORY, _("Can't open directory"));
    return;
  }

  get_msg = new_object_message_from_uri(G_VFS_BACKEND_RACK(op_backend), soup_message_get_uri(head_msg), SOUP_METHOD_GET);

  soup_message_body_set_accumulate (get_msg->response_body, FALSE);

  stream = soup_input_stream_new (op_backend->session_async, get_msg);

  soup_input_stream_send_async (stream,
                                G_PRIORITY_DEFAULT,
                                G_VFS_JOB (job)->cancellable,
                                open_for_read_ready,
                                job);
}

static gboolean
try_open_for_read (GVfsBackend        *backend,
                   GVfsJobOpenForRead *job,
                   const char         *filename)
{
  RackPath *path;
  FileType type;
  SoupMessage *msg;

  path = rack_path_new(filename);
  type = rack_path_get_type(path);

  if (type != FILE_TYPE_OBJECT)
    {
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_IS_DIRECTORY, _("Can't open directory"));
      rack_path_free(path);
      return TRUE;
    }

  msg = new_object_message(G_VFS_BACKEND_RACK(backend), path, SOUP_METHOD_HEAD);

  g_vfs_job_set_backend_data (G_VFS_JOB (job), backend, NULL);
  http_backend_queue_message (G_VFS_BACKEND(backend), msg, try_tested_object, job);

  rack_path_free(path);

  return TRUE;
}

/* *** read () *** */
static void
read_ready (GObject      *source_object,
            GAsyncResult *result,
            gpointer      user_data)
{
  GInputStream *stream;
  GVfsJob      *job;
  GError       *error;
  gssize        nread;


  stream = G_INPUT_STREAM (source_object);
  error  = NULL;
  job    = G_VFS_JOB (user_data);

  nread = g_input_stream_read_finish (stream, result, &error);

  if (nread < 0)
    {
      g_vfs_job_failed_literal (G_VFS_JOB (job),
                                error->domain,
                                error->code,
                                error->message);

      g_error_free (error);
      return;
    }

  g_vfs_job_read_set_size (G_VFS_JOB_READ (job), nread);
  g_vfs_job_succeeded (job);

}

static gboolean
try_read (GVfsBackend        *backend,
          GVfsJobRead        *job,
          GVfsBackendHandle   handle,
          char               *buffer,
          gsize               bytes_requested)
{
  GInputStream    *stream;

  g_print("[try_for_read]\n");

  stream = G_INPUT_STREAM (handle);

  g_input_stream_read_async (stream,
                             buffer,
                             bytes_requested,
                             G_PRIORITY_DEFAULT,
                             G_VFS_JOB (job)->cancellable,
                             read_ready,
                             job);
  return TRUE;
}

/* *** read_close () *** */
static void
close_read_ready (GObject      *source_object,
                  GAsyncResult *result,
                  gpointer      user_data)
{
  GInputStream *stream;
  GVfsJob      *job;
  GError       *error;
  gboolean      res;

  job = G_VFS_JOB (user_data);
  stream = G_INPUT_STREAM (source_object);
  res = g_input_stream_close_finish (stream,
                                     result,
                                     &error);
  if (res == FALSE)
    {
      g_vfs_job_failed_literal (G_VFS_JOB (job),
                                error->domain,
                                error->code,
                                error->message);

      g_error_free (error);
    }
  else
    g_vfs_job_succeeded (job);

  g_object_unref (stream);
}

static gboolean
try_close_read (GVfsBackend       *backend,
                GVfsJobCloseRead  *job,
                GVfsBackendHandle  handle)
{
  GInputStream    *stream;

  stream = G_INPUT_STREAM (handle);

  g_input_stream_close_async (stream,
                              G_PRIORITY_DEFAULT,
                              G_VFS_JOB (job)->cancellable,
                              close_read_ready,
                              job);
  return TRUE;
}

static void
write_ready (GObject      *source_object,
             GAsyncResult *result,
             gpointer      user_data)
{
  g_print("[write_ready]\n");
  GOutputStream *stream;
  GVfsJob       *job;
  GError        *error;
  gssize         nwrote;

  stream = G_OUTPUT_STREAM (source_object);
  error  = NULL;
  job    = G_VFS_JOB (user_data);

  nwrote = g_output_stream_write_finish (stream, result, &error);

  if (nwrote < 0)
    {
      g_vfs_job_failed_literal (G_VFS_JOB (job),
                                error->domain,
                                error->code,
                                error->message);

      g_error_free (error);
      return;
    }

  g_vfs_job_write_set_written_size (G_VFS_JOB_WRITE (job), nwrote);
  g_vfs_job_succeeded (job);
}


static gboolean
try_write (GVfsBackend *backend,
           GVfsJobWrite *job,
           GVfsBackendHandle handle,
           char *buffer,
           gsize buffer_size)
{
  g_print("[try_write]\n");
  GOutputStream   *stream;

  stream = G_OUTPUT_STREAM (handle);

  g_output_stream_write_async (stream,
                               buffer,
                               buffer_size,
                               G_PRIORITY_DEFAULT,
                               G_VFS_JOB (job)->cancellable,
                               write_ready,
                               job);
  return TRUE;
}

/* *** replace () *** */
static void
open_for_replace_succeeded (GVfsBackendRack *op_backend, GVfsJob *job,
                            const char *filename, const char *etag)
{
  SoupMessage     *put_msg;
  GOutputStream   *stream;
  RackPath *path;

  path = rack_path_new(filename);
  put_msg = new_object_message(op_backend, path, SOUP_METHOD_PUT);
  rack_path_free(path);

  /*if (etag)
    soup_message_headers_append (put_msg->request_headers, "If-Match", etag);
  */
  stream = soup_output_stream_new (G_VFS_BACKEND_HTTP(op_backend)->session, put_msg, -1);
  g_object_unref (put_msg);

  g_vfs_job_open_for_write_set_handle (G_VFS_JOB_OPEN_FOR_WRITE (job), stream);
  g_vfs_job_succeeded (job);
}

static gboolean
try_replace (GVfsBackend *backend,
             GVfsJobOpenForWrite *job,
             const char *filename,
             const char *etag,
             gboolean make_backup,
             GFileCreateFlags flags)
{
  g_print("[try_replace]\n");
  GVfsBackendHttp *op_backend;

  /* TODO: if SoupOutputStream supported chunked requests, we could
   * use a PUT with "If-Match: ..." and "Expect: 100-continue"
   */

  op_backend = G_VFS_BACKEND_HTTP (backend);

  if (make_backup)
    {
      g_vfs_job_failed (G_VFS_JOB (job),
                        G_IO_ERROR,
                        G_IO_ERROR_CANT_CREATE_BACKUP,
                        _("Backup file creation failed"));
      return TRUE;
    }

  open_for_replace_succeeded (G_VFS_BACKEND_RACK(op_backend), G_VFS_JOB (job), filename, NULL);
  return TRUE;
}

static void
try_created_object (SoupSession *session, SoupMessage *create_msg, 
		    gpointer user_data)
{
  GVfsJob *job = G_VFS_JOB (user_data);
  GVfsBackendHttp *op_backend = job->backend_data;
  GOutputStream   *stream;
  SoupMessage	  *write_msg;

  guint ret = create_msg->status_code;

  if(ret != SOUP_STATUS_CREATED) {
    g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), create_msg->reason_phrase);
    return;
  } 

  write_msg = new_object_message_from_uri(G_VFS_BACKEND_RACK(op_backend), soup_message_get_uri(create_msg), SOUP_METHOD_PUT);

  stream = soup_output_stream_new (op_backend->session, write_msg, -1);
  g_object_unref (write_msg);

  g_vfs_job_open_for_write_set_handle (G_VFS_JOB_OPEN_FOR_WRITE (job), stream);
  g_vfs_job_succeeded (job);
}

static void
try_create_tested_existence (SoupSession *session, SoupMessage *msg,
                             gpointer user_data)
{
  GVfsJob *job = G_VFS_JOB (user_data);
  GVfsBackendHttp *op_backend = job->backend_data;
  SoupMessage     *create_msg;

  if (SOUP_STATUS_NOT_FOUND != msg->status_code)
    {
      g_vfs_job_failed (job,
                        G_IO_ERROR,
                        G_IO_ERROR_EXISTS,
                        _("Target file already exists"));
      return;
    }

  create_msg = new_object_message_from_uri(G_VFS_BACKEND_RACK(op_backend), soup_message_get_uri(msg), SOUP_METHOD_PUT);

  // Create a zero-length file before signalling success
  soup_message_headers_append(create_msg->request_headers, "Content-Length", "0");
  soup_message_headers_append(create_msg->request_headers, "Content-Type", "application/octet-stream");
  http_backend_queue_message (G_VFS_BACKEND(op_backend), create_msg, try_created_object, job);
}


static gboolean
try_create (GVfsBackend *backend,
            GVfsJobOpenForWrite *job,
            const char *filename,
            GFileCreateFlags flags)
{
  g_printf("[try_create]\n");
  SoupMessage *msg;

  /* TODO: if SoupOutputStream supported chunked requests, we could
   * use a PUT with "If-None-Match: *" and "Expect: 100-continue"
   */

  RackPath *path = rack_path_new(filename);
  msg = new_object_message(G_VFS_BACKEND_RACK(backend), path, SOUP_METHOD_HEAD);
  rack_path_free(path);

  g_vfs_job_set_backend_data (G_VFS_JOB (job), backend, NULL);

  http_backend_queue_message (backend, msg, try_create_tested_existence, job);

  return TRUE;
}

/* *** close_write () *** */
static void
close_write_ready (GObject      *source_object,
                   GAsyncResult *result,
                   gpointer      user_data)
{
  GOutputStream *stream;
  GVfsJob       *job;
  GError        *error;
  gboolean       res;

  error = NULL;
  job = G_VFS_JOB (user_data);
  stream = G_OUTPUT_STREAM (source_object);
  res = g_output_stream_close_finish (stream,
                                      result,
                                      &error);
  if (res == FALSE)
    {
      g_vfs_job_failed_literal (G_VFS_JOB (job),
                                error->domain,
                                error->code,
                                error->message);

      g_error_free (error);
    }
  else
    g_vfs_job_succeeded (job);

  g_object_unref (stream);
}

static gboolean
try_close_write (GVfsBackend *backend,
                 GVfsJobCloseWrite *job,
                 GVfsBackendHandle handle)
{
  GOutputStream   *stream;

  stream = G_OUTPUT_STREAM (handle);

  g_output_stream_close_async (stream,
                               G_PRIORITY_DEFAULT,
                               G_VFS_JOB (job)->cancellable,
                               close_write_ready,
                               job);

  return TRUE;
}

static gboolean
try_query_settable_attributes (GVfsBackend *backend,
                               GVfsJobQueryAttributes *job,
                               const char *filename)
{
  GFileAttributeInfoList *list;
  RackPath *path;
  FileType type;

  path = rack_path_new(filename);
  type = rack_path_get_type(path);
  list = g_file_attribute_info_list_new();

  if(type == FILE_TYPE_CONTAINER)
  {
    g_file_attribute_info_list_add(list,
      RACK_ATTRIBUTE_CDN_ENABLED,
      G_FILE_ATTRIBUTE_TYPE_BOOLEAN,
      G_FILE_ATTRIBUTE_INFO_NONE);

    g_file_attribute_info_list_add(list,
     RACK_ATTRIBUTE_CDN_TTL,
     G_FILE_ATTRIBUTE_TYPE_UINT32,
     G_FILE_ATTRIBUTE_INFO_NONE);

    g_file_attribute_info_list_add(list,
     RACK_ATTRIBUTE_CDN_USER_AGENT_ACL,
     G_FILE_ATTRIBUTE_TYPE_STRING,
     G_FILE_ATTRIBUTE_INFO_NONE);

    g_file_attribute_info_list_add(list,
     RACK_ATTRIBUTE_CDN_REFERRER_ACL,
     G_FILE_ATTRIBUTE_TYPE_STRING,
     G_FILE_ATTRIBUTE_INFO_NONE);
  }

  g_vfs_job_query_attributes_set_list(job, list);
  g_vfs_job_succeeded(G_VFS_JOB(job));

  g_file_attribute_info_list_unref(list);
  rack_path_free(path);
  return TRUE;
}

static void
container_enable_cdn_initial(GVfsBackendRack *rack,
                             GVfsJobSetAttribute *job,
			     RackPath *path)
{
  SoupMessage *msg;
  guint ret;

  msg = new_container_cdn_message(rack, path, SOUP_METHOD_PUT);
  ret = http_backend_send_message(G_VFS_BACKEND(rack), msg); 

  switch(ret) 
    {
    case SOUP_STATUS_CREATED:
    case SOUP_STATUS_ACCEPTED:
      g_vfs_job_succeeded(G_VFS_JOB(job));
      break;
    case SOUP_STATUS_NOT_FOUND:	
      g_vfs_job_failed (G_VFS_JOB (job), G_IO_ERROR, G_IO_ERROR_NOT_FOUND,_("Container not found"));
      break;
    default:
      g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
    }

  g_object_unref(msg);
}

// is there something that will do this for me??
static gboolean
parse_boolean(const char *str)
{
  if(!str) return FALSE;
  if(!g_strcmp0("TRUE", str)) return TRUE;
  if(!g_strcmp0("True", str)) return TRUE;
  if(!g_strcmp0("true", str)) return TRUE;
  return FALSE;
}

static void
do_set_attribute (GVfsBackend *backend,
                  GVfsJobSetAttribute *job,
                  const char *filename,
                  const char *attribute,
                  GFileAttributeType type,
                  gpointer value_p,
                  GFileQueryInfoFlags flags)
{
  RackPath *path; 
  FileType file_type;
  SoupMessage *msg;
  gboolean matched;
  gboolean cdn_enabled;

  path = rack_path_new(filename);
  file_type = rack_path_get_type(path);
  matched = TRUE;
  cdn_enabled = FALSE;

  if(file_type != FILE_TYPE_CONTAINER)
  {
    g_vfs_job_failed (G_VFS_JOB (job), G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,_("Operation not supported by backend"));
    rack_path_free(path);
    return;
  }

  msg = new_container_cdn_message(G_VFS_BACKEND_RACK(backend), path, SOUP_METHOD_POST);

  if(!g_strcmp0(attribute, RACK_ATTRIBUTE_CDN_ENABLED)) 
  {
    cdn_enabled = parse_boolean((char*)value_p);
    soup_message_headers_append(msg->request_headers, "X-CDN-Enabled", (cdn_enabled? "True" : "False"));
  }
  else if(!g_strcmp0(attribute, RACK_ATTRIBUTE_CDN_TTL))
  {
    soup_message_headers_append(msg->request_headers, "X-TTL", (char*)value_p);
  }
  else if(!g_strcmp0(attribute, RACK_ATTRIBUTE_CDN_LOG_RETENTION))
  {
    gboolean retention = parse_boolean((char*)value_p);
    soup_message_headers_append(msg->request_headers , "X-Log-Retention", (retention? "True" : "False"));
  }
  else if(!g_strcmp0(attribute, RACK_ATTRIBUTE_CDN_USER_AGENT_ACL))
  {
    soup_message_headers_append(msg->request_headers, "X-User-Agent-ACL", (char*) value_p); 
  }
  else if(!g_strcmp0(attribute, RACK_ATTRIBUTE_CDN_REFERRER_ACL))
  {
    soup_message_headers_append(msg->request_headers, "X-Referrer-ACL", (char*) value_p);
  }
  else
  {
    matched = FALSE;
  }

  if(matched) 
  {
    guint ret = http_backend_send_message(backend, msg); 
    switch(ret) 
      {
      case SOUP_STATUS_ACCEPTED:
	g_vfs_job_succeeded(G_VFS_JOB(job));
	break;
      case SOUP_STATUS_NOT_FOUND:
	if(cdn_enabled) 
	{
	  // The first time the container is CDN-enabled it must be added with a 
	  // PUT request. Subsequent enable/disable operations can be done with
	  // a POST like any other attribute
	  container_enable_cdn_initial(G_VFS_BACKEND_RACK(backend), job, path);
	}
	else
	{
	  g_vfs_job_failed (G_VFS_JOB (job), G_IO_ERROR, G_IO_ERROR_NOT_FOUND,_("Container not found"));
	}
	break;
      default:
	g_vfs_job_failed(G_VFS_JOB(job), G_IO_ERROR, G_IO_ERROR_FAILED, _("HTTP Error: %s"), msg->reason_phrase);
      }
  }
  else
  {
    g_vfs_job_failed (G_VFS_JOB (job), G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,_("Attribute not supported"));
  }
  
  g_object_unref(msg);
  rack_path_free(path);
}

static void
g_vfs_backend_rack_class_init (GVfsBackendRackClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GVfsBackendClass *backend_class = G_VFS_BACKEND_CLASS (klass);

  id_q = g_quark_from_static_string ("command-id");

  gobject_class->finalize = g_vfs_backend_rack_finalize;

  backend_class->mount = do_mount;
  backend_class->enumerate = do_enumerate;
  backend_class->query_info = do_query_info;
  backend_class->make_directory = do_make_directory;
  backend_class->delete = do_delete;
  backend_class->try_open_for_read = try_open_for_read;
  backend_class->try_read = try_read;
  backend_class->try_close_read = try_close_read;
  backend_class->try_write = try_write;
  backend_class->try_replace = try_replace;
  backend_class->try_create = try_create;
  backend_class->try_unmount = try_unmount;
  backend_class->try_close_write = try_close_write;
  backend_class->set_display_name = NULL; // Renaming isn't supported
  backend_class->try_mount = NULL;
  backend_class->try_query_info = NULL;
  backend_class->try_query_settable_attributes = try_query_settable_attributes;
  backend_class->set_attribute = do_set_attribute;
}
