#ifndef RANGER_AGENT_PDK_PLUGINGAPI_H
#define RANGER_AGENT_PDK_PLUGINGAPI_H

#ifdef __cplusplus
extern "C" {
#endif

#define RANGER_WIN32_ENABLE		0

#if RANGER_WIN32_ENABLE > 0
#define PATH_SEPERATOR  '\\'
#define MAX_PATH        _MAX_PATH
#else
#define PATH_SEPERATOR  '/'
#define MAX_PATH        PATH_MAX
#endif


struct ServerDetector_;

typedef struct PluginAPI_ {

    int (*fn_register_server_detector)(struct ServerDetector_*);
    int (*fn_unregister_server_detector)(const char* name);
    void (*fn_iterate_server_detectors)(GFunc user_func, void* user_data);
    GList* (*fn_get_server_detectors)(void);
    void (*fn_put_server_detectors)(GList*);

    /**
     * Wrapper for Sigar's ProcessFinder.find method.
     * @param query SIGAR Process Table Query
     * @return Array of pids that match the query, length == 0 if
     * there were no matches.
     */
    GList*    (*fn_get_pids)(const char* ptql_query);

    /* 0: success, -1: failure */
    int    (*fn_get_proc_exe)(long pid, char* buffer, size_t size );

    /* 0: success, -1: failure */
    int (*fn_get_parent_dir)(const char* path, int levels, char* buffer, size_t size );
	
}PluginAPI;

extern PluginAPI   plugin_api;

int plugin_api_init(void);
void plugin_api_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* RANGER_AGENT_API_H */

