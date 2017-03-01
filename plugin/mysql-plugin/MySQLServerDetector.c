
#include <pdk/pdk.h>

// likely will only work w/ linux due to permissions
// and setting of argv[0] to the full binary path.
#define PTQL_QUERY		"State.Name.eq=mysqld"

#define VERSION_3       "3.x"
#define VERSION_4       "4.x"
#define VERSION_5       "5.x"

static GList* auto_detect_i(void);
static GList* file_detect_i(const char* path);

static ServerDetector  mySQLServerDetector = {
    .type = "mysql",
    .fn_auto_detect = auto_detect_i,
    .fn_file_detect = file_detect_i,
};

static void pid_list_iterator(gpointer data, gpointer user_data) 
{
    GList  **paths = (GList  **)user_data ;
    char exe[MAX_PATH], installPath[MAX_PATH];
    int  retcode;
    GStatBuf fstat;
	
    retcode = plugin_api.fn_get_proc_exe((long)data, exe, MAX_PATH);
    if( retcode != 0 ){
        return;
    }

    if( ! g_path_is_absolute(exe) ) {
        return;
    }

    // mysqld is usually kept in ${install}/bin or
    // ${install}/libexec (gentoo). move up one directory
    // and check for safe_mysqld (3.x) or mysqld_safe (4.x)
    if( plugin_api.fn_get_parent_dir(exe, 2, installPath, MAX_PATH ) != 0 ){
        return;
    }

    // Handle 5.x and 4.x servers
    snprintf(exe, MAX_PATH, "%s%c%s%c%s", 
        installPath, PATH_SEPERATOR, "bin",PATH_SEPERATOR, "mysqld_safe" );
    if( g_stat ( exe,  &fstat  ) == 0 ) {
        goto end;
    }

    // Handle 3.x servers
    snprintf(exe, MAX_PATH, "%s%c%s%c%s", 
        installPath, PATH_SEPERATOR, "bin",PATH_SEPERATOR, "safe_mysqld" );
    if( g_stat ( exe, &fstat ) == 0 ) {
        goto end;
    }

end:	
    *paths = g_list_append(*paths, g_strdup(exe));
}

/**
 * Helper method to discover MySQL servers using the process table
 */
static GList*  get_server_process_list_i(void)
{
    GList  *pids, *paths;

    pids = plugin_api.fn_get_pids(PTQL_QUERY);
    if( pids == NULL ) {
        return NULL;
    }

    paths = NULL;
    g_list_foreach(pids, (GFunc)pid_list_iterator, &paths );

    g_list_free( pids );

    return paths;
}

static GList* get_server_values_i(
    const char* path, const char*  version)
{
    char identifer[MAX_IDENTIFIER];
    GList* servers = NULL;
	
    ServerResource * server = server_resource_create();

     // Avoid clash with HQ 2.0 AI identifier for MySQL databases
    snprintf(identifer, MAX_IDENTIFIER, "%s:%s:%s", 
        mySQLServerDetector.name, version, path);
    server_resource_set_identifier(server,identifer);
    server_resource_set_type(server,mySQLServerDetector.name);
    server_resource_set_version(server,version);
    
    servers = g_list_append(servers, server);

    return servers;
}
 

static GList* file_detect_i(const char* path)
{
    if( strlen(path) >= strlen("safe_mysqld") &&
        strcmp(path + strlen(path) - strlen("safe_mysqld"), "safe_mysqld") == 0 ) {
        /* mysql VERSION_3 */
        
        return get_server_values_i(path, VERSION_3 );
    }

    if( strlen(path) >= strlen("mysqld_safe") &&
        strcmp(path + strlen(path) - strlen("mysqld_safe"), "mysqld_safe") == 0 ) {
        /* mysql VERSION_4 */

        char dirname[MAX_PATH], filename[MAX_PATH];
	    GStatBuf fstat;

        if( plugin_api.fn_get_parent_dir(path, 2, dirname, MAX_PATH ) == 0 ) {
            // 4.x versions include isamchk
            sprintf(filename, "%s%c%s%c%s", dirname, 
                PATH_SEPERATOR,"bin", PATH_SEPERATOR, "isamchk");
            if( g_stat ( filename, &fstat ) == 0 ) {
                sprintf(filename, "%s%c%s%c%s", dirname, 
                    PATH_SEPERATOR,"bin", PATH_SEPERATOR, "myisamchk");
                if( g_stat ( filename, &fstat ) != 0 ) {
                    return get_server_values_i(path, VERSION_4 );
                }
            } else {
                // 5.x no longer includes isamchk
                sprintf(filename, "%s%c%s%c%s", dirname, 
                    PATH_SEPERATOR,"bin", PATH_SEPERATOR, "myisamchk");
                if( g_stat ( filename, &fstat ) == 0 ) {
                    return get_server_values_i(path, VERSION_5 );
                }
            }

            
        }
    }

    return NULL;
}


/**
 * Auto scan
 */
static GList* auto_detect_i(void)
{
    GList  *servers = NULL;
    GList  *paths;
    int i;

    paths = get_server_process_list_i();
    for( i = 0 ; i < g_list_length(paths); i++ ) {
        GList * found;
        char * path = g_list_nth_data( paths, i );

        found = file_detect_i( path ); 
        if( g_list_length( found ) > 0 ) {
            servers = g_list_concat(servers, found );
        }
    }

    g_list_free_full( paths, g_free );

    return servers;
}

static void __attribute__((constructor)) module_register(void)
{
    plugin_api.fn_register_server_detector(&mySQLServerDetector);
    return;
}


