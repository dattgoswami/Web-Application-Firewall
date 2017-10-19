/* mod_firewall.c: */
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

#include "mod_firewall.h"

/*
 ==============================================================================
 Our configuration prototype and declaration:
 ==============================================================================
 */
typedef struct {
    int         enabled;      /* Enable or disable our module */
    const char *path;         /* Some path to...something */
    int         typeOfAction; /* 1 means action A, 2 means action B and so on */
} firewall_config;

static firewall_config config;

/*
 ==============================================================================
 Our directive handlers:
 ==============================================================================
 */
/* Handler for the "FirewallEnabled" directive */
const char *firewall_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(!strcasecmp(arg, "on")) config.enabled = 1;
    else config.enabled = 0;
    return NULL;
}

/* Handler for the "firewallPath" directive */
const char *firewall_set_path(cmd_parms *cmd, void *cfg, const char *arg)
{
    config.path = arg;
    return NULL;
}

/* Handler for the "firewallAction" directive */
/* Let's pretend this one takes one argument (file or db), and a second (deny or allow), */
/* and we store it in a bit-wise manner. */
const char *firewall_set_action(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2)
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
static const command_rec        firewall_directives[] =
{
    AP_INIT_TAKE1("firewallEnabled", firewall_set_enabled, NULL, RSRC_CONF, "Enable or disable mod_firewall"),
    AP_INIT_TAKE1("firewallPath", firewall_set_path, NULL, RSRC_CONF, "The path to whatever"),
    AP_INIT_TAKE2("firewallAction", firewall_set_action, NULL, RSRC_CONF, "Special action value!"),
    { NULL }
};
/*
 ==============================================================================
 Our module handler:
 ==============================================================================
 */

static int process_req(request_rec *r){
  apr_file_t * fd;
  apr_fileperms_t perm = APR_OS_DEFAULT;
  char *buffer, *rbuffer;
  int ch_sz = sizeof(char);
  int buflen = 0, rbuflen = 0;
  apr_status_t err = 0;
  int retval = 1;
  if ((err = apr_initialize()) != APR_SUCCESS) 
  {
      char tmp_buf[TMP_BUF_LEN];
      ap_rprintf(r, "ERROR APR_INIT: %s", apr_strerror(err, tmp_buf, TMP_BUF_LEN));
      goto err_exit;
  }

  buffer = (char *)malloc(sizeof(char) * MAX_REC_LEN);
  if(!buffer)	goto err_exit;
   
  if(r->method_number == M_POST){
    char tmpbuf[MAX_REC_LEN] = {0};
    read_post(r, tmpbuf, MAX_REC_LEN);
    snprintf(buffer,MAX_REC_LEN,  "%s", tmpbuf);
  }
  else{ 
    snprintf(buffer,MAX_REC_LEN,  "%s",	r->args);
  }
  buflen = strlen(buffer)+1;
  
  if(!check_rules(r, buffer, buflen)){
  	retval = 0;
  	ap_rprintf(r, "%d retval:0", __LINE__);
  	goto err_exit;
  }
  
  /*Clean UP*/
  err_exit:
  if(fd)		apr_file_close(fd);
  if(buffer)	free(buffer);
  return retval;
}

static int firewall_handler(request_rec *r)
{
  if(!r->handler || strcmp(r->handler, "firewall_handler")) return(DECLINED);
  
/*  ap_set_content_type(r, "text/html;charset=ascii") ;
  ap_rputs(
	"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n", r) ;
  ap_rputs(
	"<html><head><title>Apache HelloWorld Module</title></head>", r) ;
  ap_rputs("<body><h1>Hello World!</h1>", r) ;
  
  ap_rputs("<p>This is the Apache AVK HelloWorld module!</p>", r) ;
  ap_rprintf(r, "<p>This is URI %s</p>", r->uri);
  ap_rprintf(r, "<p>This is the_request %s</p>", r->the_request);
  ap_rprintf(r, "<p>This is args %s</p>", r->args);
  ap_rprintf(r, "<p>This is path_info %s</p>", r->path_info);
  */
  if(!process_req(r)){
  	ap_rprintf(r, "%d retval:0", __LINE__);
  	return DONE;
  }
  /* Print the headers and env */
  /* Note that the response headers and environment may be empty at
   * this point.  The CGI environment is an overhead we dispense
   * with in a module, unless another module that requires it
   * (e.g. mod_rewrite) has set it up.
   */
  /*
  //read_post(r);
  printtable(r, r->headers_in, "Request Headers", "Header", "Value") ;
  printtable(r, r->headers_out, "Response Headers", "Header", "Value") ;
  printtable(r, r->subprocess_env, "Environment", "Variable", "Value") ;
  if(r->body_table)
    printtable(r, r->body_table, "Body Table", "Variable", "Value") ;
  else
    ap_rprintf(r, "<p>Body table is null</p>");  
  printtable(r, r->notes, "Notes", "Variable", "Value") ;
  printtable(r, r->trailers_in, "Trailers in", "Variable", "Value") ;
  printtable(r, r->trailers_out, "Trailers out", "Variable", "Value") ;
  ap_rputs("</body></html>", r) ;
  */

  return DECLINED;
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
    ap_hook_handler(firewall_handler, NULL, NULL, APR_HOOK_FIRST);
}
/*
 ==============================================================================
 Our module name tag:
 ==============================================================================
 */
module AP_MODULE_DECLARE_DATA   firewall_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,               /* Per-directory configuration handler */
    NULL,               /* Merge handler for per-directory configurations */
    NULL,               /* Per-server configuration handler */
    NULL,               /* Merge handler for per-server configurations */
    firewall_directives, /* Any directives we may have for httpd */
    register_hooks      /* Our hook registering function */
};
