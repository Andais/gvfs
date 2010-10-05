## gvfs-openstack - gvfs backend for [OpenStack Object Storage](http://openstack.org/projects/storage/)
Author: Ryan Brown <<r@nodr.org>>

###Usage
To mount a [Rackspace Cloud Files](http://www.rackspacecloud.com/cloud_hosting_products/files) account in nautilus, use a URL like this:  

    rack://username@auth.api.rackspacecloud.com

(The password is the API key available from the Rackspace Cloud control panel)  

###CDN Attributes
  gvfs-openstack supports container CDN operations through the GVFS metadata API.

  Examples:

    CDN-enable a container:
        $ gvfs-set-attribute rack://username@host/container cdn::enabled true

    View the current CDN configuration:
        $ gvfs-info rack://username@auth.api.rackspacecloud.com/container

            cdn::enabled: TRUE
            cdn::uri: http://c000xxxxx.cdn1.cloudfiles.rackspacecloud.com
            cdn::ttl: 259200 (in seconds)
            cdn::log-retention: TRUE
            cdn::user-agent-acl: 
            cdn::referrer-acl: 

    Change a CDN attribute:
        $ gvfs-set-attribute rack://username@host/container cdn::ttl 300
