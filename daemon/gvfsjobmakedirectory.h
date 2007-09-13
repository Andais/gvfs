#ifndef __G_VFS_JOB_MAKE_DIRECTORY_H__
#define __G_VFS_JOB_MAKE_DIRECTORY_H__

#include <gio/gfileinfo.h>
#include <gvfsjob.h>
#include <gvfsjobdbus.h>
#include <gvfsbackend.h>

G_BEGIN_DECLS

#define G_VFS_TYPE_JOB_MAKE_DIRECTORY         (g_vfs_job_make_directory_get_type ())
#define G_VFS_JOB_MAKE_DIRECTORY(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), G_VFS_TYPE_JOB_MAKE_DIRECTORY, GVfsJobMakeDirectory))
#define G_VFS_JOB_MAKE_DIRECTORY_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), G_VFS_TYPE_JOB_MAKE_DIRECTORY, GVfsJobMakeDirectoryClass))
#define G_VFS_IS_JOB_MAKE_DIRECTORY(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), G_VFS_TYPE_JOB_MAKE_DIRECTORY))
#define G_VFS_IS_JOB_MAKE_DIRECTORY_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), G_VFS_TYPE_JOB_MAKE_DIRECTORY))
#define G_VFS_JOB_MAKE_DIRECTORY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), G_VFS_TYPE_JOB_MAKE_DIRECTORY, GVfsJobMakeDirectoryClass))

typedef struct _GVfsJobMakeDirectoryClass   GVfsJobMakeDirectoryClass;

struct _GVfsJobMakeDirectory
{
  GVfsJobDBus parent_instance;

  GVfsBackend *backend;
  char *filename;
};

struct _GVfsJobMakeDirectoryClass
{
  GVfsJobDBusClass parent_class;
};

GType g_vfs_job_make_directory_get_type (void) G_GNUC_CONST;

GVfsJob *g_vfs_job_make_directory_new (DBusConnection *connection,
			       DBusMessage    *message,
			       GVfsBackend    *backend);

G_END_DECLS

#endif /* __G_VFS_JOB_MAKE_DIRECTORY_H__ */