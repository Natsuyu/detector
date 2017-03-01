
#include <pdk/pdk.h>

static sigar_t    *sigar;
static GRWLock   data_lock;

static GList     *server_detector_list;

/**
 * Chop the last element off a path.  For example, if you pass in
 * /usr/local/foo then this will return /usr/local
 * If there is not enough to chop off, this throws IllegalArgumentException
 */
static int  
get_parent_dir_i(const char* path, int levels, char* buffer, size_t size )
{
    char* index;
    char temp[MAX_PATH];

    if( levels == 0 ) {
        snprintf(buffer, size, "%s", path);
        return 0;
    }

    strcpy(temp, path);
	
    while( levels-- > 0 ) {
        index = strrchr( temp, PATH_SEPERATOR );
        if( index == NULL ) {
            return -1;
        }
        *index= 0;
    }

    snprintf(buffer, size, "%s", temp);

    return 0;
}


static GList*  get_pids_i(const char* ptql)
{
    sigar_ptql_error_t error;
    sigar_ptql_query_t *query; 
    sigar_proc_list_t proclist;
    int status;
    GList* pids = NULL;
    char * temp = g_strdup(ptql);

    status = sigar_ptql_query_create(&query, temp, &error);
    if( status != SIGAR_OK ){
        g_free(temp);
        return NULL;
    }
    g_free(temp);

    status = sigar_ptql_query_find( sigar, query, &proclist);
    if( status == SIGAR_OK ){
        int i;
        for( i = 0; i < proclist.number; i++ ) {
            pids = g_list_append(pids, (gpointer)proclist.data[i] );
        }
    }

    sigar_proc_list_destroy(sigar,&proclist);
    sigar_ptql_query_destroy(query);

    return pids;
}

static int   get_proc_exe_i(long pid, char* buffer, size_t size )
{
    int status;
    sigar_proc_exe_t procexe;

    status = sigar_proc_exe_get(sigar, (sigar_pid_t)pid, &procexe ); 
    if( status != SIGAR_OK ){
        ERROR("sigar:use superuser privilege!");
        return -1;
    }

    snprintf(buffer, size, "%s", procexe.name );

    return 0;
}

static int register_server_detector_i(ServerDetector* detector)
{
    int i;

    g_rw_lock_writer_lock(&data_lock);
    for( i = 0 ; i < g_list_length(server_detector_list); i++ ) {
        ServerDetector* temp = g_list_nth_data( server_detector_list, i );
        if( strcasecmp(temp->type, detector->type ) == 0 ) {
            return -1;
        }
    }
    ServerDetectorReference(detector);
    server_detector_list = g_list_append(server_detector_list, detector );
    g_rw_lock_writer_unlock(&data_lock);

    return 0;
}

static int unregister_server_detector_i(const char* type)
{
    int i;

    g_rw_lock_writer_lock(&data_lock);
    for( i = 0 ; i < g_list_length(server_detector_list); i++ ) {
        GList * entry = g_list_nth(server_detector_list,i);
        ServerDetector* detector = g_list_nth_data( server_detector_list, i );
        if( strcasecmp(detector->type, type ) == 0 ) {
            ServerDetectorDeReference(detector);
            server_detector_list = g_list_delete_link(server_detector_list,entry);
            return 0;
        }
    }
    g_rw_lock_writer_unlock(&data_lock);

    return -1;
}

static void iterate_server_detectors_i(GFunc user_func, void* user_data)
{
    g_list_foreach(server_detector_list, user_func, user_data );
}

static GList* get_server_detectors_i(void)
{
    GList* detectors = NULL;
    int i;

    g_rw_lock_reader_lock(&data_lock);
    for( i = 0 ; i < g_list_length(server_detector_list); i++ ) {
        ServerDetector* detector = g_list_nth_data( server_detector_list, i );
        ServerDetectorReference(detector);
        detectors = g_list_append(detectors,detector);
    }
    g_rw_lock_reader_unlock(&data_lock);
	
    return detectors;
}

static void put_server_detectors_i(GList* detectors)
{
    int i;
    for( i = 0 ; i < g_list_length(detectors); i++ ) {
        ServerDetector* detector = g_list_nth_data( detectors, i );
        ServerDetectorDeReference(detector);
    }
    g_list_free(detectors);
}


PluginAPI   plugin_api = {
    .fn_register_server_detector = register_server_detector_i,
    .fn_unregister_server_detector = unregister_server_detector_i,
    .fn_iterate_server_detectors = iterate_server_detectors_i,
    .fn_get_server_detectors = get_server_detectors_i,
    .fn_put_server_detectors = put_server_detectors_i,
	
    .fn_get_pids = get_pids_i,
    .fn_get_proc_exe = get_proc_exe_i,
    .fn_get_parent_dir = get_parent_dir_i,
};


int plugin_api_init(void)
{
    g_rw_lock_init(&data_lock);
    sigar_open(&sigar);

    scan_methods_init();
	
    return 0;
}

void plugin_api_cleanup(void)
{
    scan_methods_cleanup();
	
    plugin_module_free_loaded();

    g_rw_lock_clear(&data_lock);
    sigar_close( sigar );
}


