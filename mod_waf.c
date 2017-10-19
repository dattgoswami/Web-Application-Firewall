/* mod_waf.c: */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_escape.h"

#include "mod_waf.h"

/*
 ==============================================================================
 Our configuration prototype and declaration:
 ==============================================================================
 */
typedef struct {
    int         enabled;      /* Enable or disable our module */
    const char *path;         /* Some path to...something */
    int         typeOfAction; /* 1 means action A, 2 means action B and so on */
} waf_config;

static waf_config config;

/*
 ==============================================================================
 Our directive handlers:
 ==============================================================================
 */
/* Handler for the "wafEnabled" directive */
const char *waf_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(!strcasecmp(arg, "on")) config.enabled = 1;
    else config.enabled = 0;
    return NULL;
}

/* Handler for the "WafPath" directive */
const char *waf_set_path(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.path = arg;
    return NULL;
}

/* Handler for the "wafAction" directive */
/* Let's pretend this one takes one argument (file or db), and a second (deny or allow), */
/* and we store it in a bit-wise manner. */
const char *waf_set_action(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2)
{
    if(!strcasecmp(arg1, "file")) config.typeOfAction = 0x01;
    else config.typeOfAction = 0x02;
    
    if(!strcasecmp(arg2, "deny")) config.typeOfAction += 0x10;
    else config.typeOfAction += 0x20;
    return NULL;
}

/*
 ==============================================================================
 The directive structure for our name tag:
 ==============================================================================
 */
static const command_rec        waf_directives[] =
{
    AP_INIT_TAKE1("wafEnabled", waf_set_enabled, NULL, RSRC_CONF, "Enable or disable mod_waf"),
    AP_INIT_TAKE1("wafPath", waf_set_path, NULL, RSRC_CONF, "The path to whatever"),
    AP_INIT_TAKE2("wafAction", waf_set_action, NULL, RSRC_CONF, "Special action value!"),
    { NULL }
};
/*
 ==============================================================================
 Our module handler:
 ==============================================================================
 */

static int write_to_log(request_rec *r){
  apr_file_t *fd = NULL;
  apr_fileperms_t perm = APR_OS_DEFAULT;
  char* buffer = NULL;
  int ch_sz = sizeof(char);
  int buflen = 0;
  apr_pool_t *pool;
  apr_status_t err = 0;
  int retval = 1;
  char *sptr = NULL;
  char *uptr = NULL;
  char filename[TMP_BUF_LEN];

  if ((err = apr_initialize()) != APR_SUCCESS) 
  {
      char tmp_buf[TMP_BUF_LEN];
      ap_rprintf(r, "<b>ERR:</b> APR_INIT: %s", apr_strerror(err, tmp_buf, TMP_BUF_LEN));
      retval = 0;
      goto err_exit;
  }
  snprintf(filename, TMP_BUF_LEN, "%s", LOG_FILE);
  if( (err = apr_file_open(&fd, filename, APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_APPEND, perm, r->pool)) != APR_SUCCESS){
    char tmp_buf[TMP_BUF_LEN];
    ap_rprintf(r, "<b>ERR:</b> File open: %s", apr_strerror(err, tmp_buf, TMP_BUF_LEN));
    retval = 0;
    goto err_exit;
  }
  /*LOCK THE LOG FILE*/
  if((err = apr_file_lock(fd, APR_FLOCK_EXCLUSIVE)) != APR_SUCCESS){
    char tmp_buf[TMP_BUF_LEN];
    ap_rprintf(r, "<b>ERR:</b> File Lock: %s", apr_strerror(err, tmp_buf, TMP_BUF_LEN));
    retval = 0;
    goto err_exit;
  }
  buffer = (char *)malloc(sizeof(char) * MAX_REC_LEN);
  if(!buffer){
    retval = 0;
    goto err_exit;
  }
   
  if(r->method_number == M_POST){
    char tmpbuf[MAX_REC_LEN] = {0};
    
    //ap_rprintf(r, "<p>In Post</p>");
    read_post(r, tmpbuf, MAX_REC_LEN);
    uptr = strdup(apr_punescape_url(r->pool, r->uri, NULL, NULL, 1));
    
    if(tmpbuf)
      sptr = strdup(apr_punescape_url(r->pool, tmpbuf, NULL, NULL, 1));
    else
      sptr = strdup("(null)\0");

    snprintf(buffer,MAX_REC_LEN,  "URI:%s, ARGS:%s\n", r->uri, sptr);
      if(!check_rules(r, sptr, MAX_REC_LEN)){
        retval = 0;
        ap_rprintf(r, "<p>Check rules failed!</p>");
        goto err_exit;
      }
  }
  else{ 
    uptr = strdup(apr_punescape_url(r->pool, r->uri, NULL, NULL, 1));
    if(r->args)
      sptr = strdup(apr_punescape_url(r->pool, r->args, NULL, NULL, 1));
    else sptr = strdup("(null)\0");
    snprintf(buffer, MAX_REC_LEN, "URI:%s, ARGS:%s\n", uptr, sptr);
    if(!check_rules(r, sptr, MAX_REC_LEN)){
        retval = 0;
        ap_rprintf(r, "<p>Check rules failed!</p>");
        goto err_exit;
    }
  }
  buflen = strlen(buffer)+1;
  apr_file_puts(buffer, fd);
  
  /*Clean UP*/
  err_exit:
  /*UNLOCK THE LOG FILE*/
  if(fd)      apr_file_unlock(fd);
  if(fd)      apr_file_close(fd);
  if(buffer)  free(buffer);
  if(uptr)    free(uptr);
  if(sptr)    free(sptr);

  return retval;
}

static int waf_handler(request_rec *r)
{
  if(!r->handler || strcmp(r->handler, "waf_handler")) return(DECLINED);
  
  if(!write_to_log(r)){
    return DONE;
  }
  else return DECLINED;
  
}

/*
 ==============================================================================
 The hook registration function (also initializes the default config values):
 ==============================================================================
 */
static void register_hooks(apr_pool_t *pool) 
{
    //config.enabled = 1;
    //config.path = "/foo/bar";
    //config.typeOfAction = 3;
    ap_hook_handler(waf_handler, NULL, NULL, APR_HOOK_LAST);
}
/*
 ==============================================================================
 Our module name tag:
 ==============================================================================
 */
module AP_MODULE_DECLARE_DATA   waf_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,               /* Per-directory configuration handler */
    NULL,               /* Merge handler for per-directory configurations */
    NULL,               /* Per-server configuration handler */
    NULL,               /* Merge handler for per-server configurations */
    waf_directives, /* Any directives we may have for httpd */
    register_hooks      /* Our hook registering function */
};
