#ifndef RANGER_AGENT_PDK_SERVER_DETECTOR_DOT_H
#define RANGER_AGENT_PDK_SERVER_DETECTOR_DOT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ServerResource_ {
    char * autoinventoryIdentifier;
    char * autoinventoryType;
    char * autoinventoryVersion;
}ServerResource;

typedef struct ServerDetector_ {
    const char * type;

    GList*  (*fn_auto_detect)(void);  /* Return: Server Resource */

    /**
     * This interface is used by the Auto-Discovery file system scan.
     * Plugins specify file patterns to match in etc/hq-server-sigs.properties
     * When a file or directory matches one of these patterns, this method
     * will be invoked.  It is up to the plugin to use the matched file or
     * directory as a hint to find server installations.
     * @param platformConfig Platform config properties.
     * @param path The absolute path to the matched file or directory.
     * @return A List of ServerResource objects representing
     * the servers that were discovered.  It is possible
     * for multiple servers to be in a single directory.
     * For example, the Covalent ERS has one directory with Apache server
     * binaries and one or more directories of configuration for each
     * server instance. 
     * This method should return null if no servers were found.
     * @throws PluginException If an error occured during server detection.
     * @see ServerResource
     */
    GList*  (*fn_file_detect)(const char* path);

#if RANGER_WIN32_ENABLE > 0
    /**
     * Performs all the actual server (and service) detection 
     * for servers detected through a WindowsRegistryScan.
     * @param platformConfig TODO
     * @param path The full path to the Windows registry key
     * @return A List of ServerResource objects representing
     * the servers that were found in the registry entry.  It is possible
     * for multiple servers to be in a single entry, although it is unusual.
     * If the registry entry being scanned is the CurrentControlSet, then only
     * a single server can be found in the entry, although the AI code does
     * not enforce this requirement.
     * This method should return null if no servers were found.
     * @throws PluginException If an error occured during server detection.
     */
    GList* (*fn_registry_detect)(const RegistryKey *current );

#endif

} ServerDetector;

/* unload the plugin */
#define ServerDetectorReference(p)
#define ServerDetectorDeReference(p)

ServerResource* server_resource_create(void);
void server_resource_destroy(void*);

static inline void server_resource_set_identifier(
    ServerResource* server, const char* value )
{
    if( server->autoinventoryIdentifier ) {
        g_free( server->autoinventoryIdentifier );
        server->autoinventoryIdentifier = NULL;
    }
    server->autoinventoryIdentifier = g_strdup(value);
}

static inline const char* 
server_resource_get_identifier( ServerResource* server )
{
    return server->autoinventoryIdentifier;
}

static inline void 
server_resource_set_type( ServerResource* server, const char* value )
{
    if( server->autoinventoryType ) {
        g_free( server->autoinventoryType );
        server->autoinventoryType = NULL;
    }
    server->autoinventoryType = g_strdup(value);
}
static inline const char* 
server_resource_get_type( ServerResource* server )
{
    return server->autoinventoryType;
}

static inline void 
server_resource_set_version( ServerResource* server, const char* value )
{
    if( server->autoinventoryVersion ) {
        g_free( server->autoinventoryVersion );
        server->autoinventoryVersion = NULL;
    }
    server->autoinventoryVersion = g_strdup(value);
}
static inline const char* 
server_resource_get_version( ServerResource* server )
{
    return server->autoinventoryVersion;
}

#ifdef __cplusplus
}
#endif

#endif /* RANGER_AGENT_PDK_SERVER_DETECTOR_DOT_H */

