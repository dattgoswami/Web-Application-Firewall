#include "common.h"
#include "mydatastructures.h"
#include "rules_checks.h"

#define MAXLEN 100
#define TMP_BUF_LEN 100
#define MAX_REC_LEN 4096
#define MAX_FILE_LEN 	255

typedef struct table_record{
	request_rec *r;
	Plist *head;
}table;
char * get_full_path(FILE* file){
    int fd;
    char procpath[MAXLEN + 1];
    char* filepath = NULL;
    if(!file) return NULL;

    fd = fileno(file);
    snprintf(procpath, MAXLEN, "/proc/self/fd/%d", fd);
    filepath = (char *)malloc(sizeof(char)*MAXLEN);
    readlink(procpath, filepath, (size_t) MAXLEN);
    return filepath;
}

static int printitem(void* rec, const char* key, const char* value) {
  /* rec is a userdata pointer.  We'll pass the request_rec in it */
  request_rec* r = rec ;
  ap_rprintf(r, "<tr><th scope=\"row\">%s</th><td>%s</td></tr>\n",
  ap_escape_html(r->pool, key), ap_escape_html(r->pool, value)) ;
  /* Zero would stop iterating; any other return value continues */
  return 1 ;
}
static void printtable(request_rec* r, apr_table_t* t,
  const char* caption, const char* keyhead, const char* valhead) {
  
  /* print a table header */
  ap_rprintf(r, "<table><caption>%s</caption><thead>"
  "<tr><th scope=\"col\">%s</th><th scope=\"col\">%s"
  "</th></tr></thead><tbody>", caption, keyhead, valhead) ;

  /* Print the data: apr_table_do iterates over entries with our callback */
  apr_table_do(printitem, r, t, NULL) ;

  /* and finish the table */
  ap_rputs("</tbody></table>\n", r) ;
}

static int writeitem(void* t, const char* key, const char* value) {
  /* rec is a userdata pointer.  We'll pass the request_rec in it */
  table *tbl = (table *)t;
  request_rec* r = tbl->r;
  insert_plist(&tbl->head, ap_escape_html(r->pool, key), 
  	ap_escape_html(r->pool, value), -1);
  return 1;
}
static Plist* fill_headers(request_rec* r, apr_table_t* t){
  
  table tbl;

  tbl.r = r;
  tbl.head = NULL;
  apr_table_do(writeitem, (void *)&tbl, t, NULL) ;
  return tbl.head;
}
void create_header_rules(Plist **hlist, char *buffer, int buflen){
	char *key = NULL, *val = NULL, *ptr = NULL;
	if(!hlist) return;

	/*Eg: User-Agent,CONTAINS:"<script>*/
	ptr = strchr(buffer, ',');
  	if(ptr){
	  	*ptr = '\0';
	  	key = buffer;
	  	val = ++ptr;
		ptr = strchr(val, ':');
		if(ptr)
			val = ++ptr;
		else
			val = NULL;
		insert_plist(hlist, key, val, 0);
	}
}
void create_method_rules(Plist **hlist, char *buffer, int buflen, request_rec *r){
	char *key = NULL, *val = NULL, *ptr = NULL;
	if(!hlist) return;

	/*Eg: GET,PARAMETER:*,CONTAINS:"union all select" */
	
	ptr = strchr(buffer, ':');
  	
  	if(ptr){
	  	key = ++ptr;
		ptr = strchr(key, ',');
		
		if(ptr){
			*ptr = '\0';
			val = ++ptr;
			ptr = strchr(val, ':');
			if(ptr)
				val = ++ptr;
			else
				val = NULL;
			insert_plist(hlist, key, val, 1);
		}
		
	}
	
}
static Plist* fill_header_rules(request_rec *r){
  apr_file_t *fd = NULL;
  apr_fileperms_t perm = APR_OS_DEFAULT;
  char *rbuffer = NULL, *tmp_buf = NULL;
  int rbuflen = 0, rlen = 0;
  apr_status_t err = 0;
  Plist *retval = NULL;
  char *key = NULL, *val = NULL;
  char filename[TMP_BUF_LEN];

  snprintf(filename, TMP_BUF_LEN, "%s", GENERAL_RULES_FILE);
  if((err = apr_file_open(&fd, filename,
  	APR_FOPEN_READ, perm, r->pool)) != APR_SUCCESS){
    char tmp_buf[TMP_BUF_LEN];
    ap_rprintf(r, "<p>Error File open: %s</p>", apr_strerror(err, tmp_buf, TMP_BUF_LEN));
    goto err_exit;
  }

  rbuffer = (char *)malloc(sizeof(char)*MAX_REC_LEN);
  rbuflen = MAX_REC_LEN;
  rbuffer[0] = '\0';
  while(apr_file_gets(rbuffer, rbuflen, fd) == APR_SUCCESS){
  	char *ptr;
  	rlen = strlen(rbuffer);
  	tmp_buf = ap_escape_html(r->pool, rbuffer);
  	//ap_rprintf(r, "<p>DBG: %s</p>", tmp_buf);
  	if(tmp_buf[rlen-1] == '\n')
  		tmp_buf[rlen-1] = '\0';
  	ptr = strchr(tmp_buf, ':');
  	if(ptr){
	  	*ptr = '\0';
	  	key = tmp_buf;
	  	val = ++ptr;
	  	if(!strcmp(key, "HEADER")){
	 		/*Eg: HEADER:User-Agent,CONTAINS:"<script>" */ 
	 		create_header_rules(&retval, val, rlen);
	  	}
	  	else if(!strcmp(key, "REQUEST_METHOD")){
	  		/*Eg: REQUEST_METHOD:GET,PARAMETER:*,CONTAINS:"union all select"*/
	  		create_method_rules(&retval, val, rlen, r); 
	  	}
  	}
  }

  /*CLean Up*/
  err_exit:
  if(rbuffer) 		free(rbuffer);
  if(fd) 		apr_file_close(fd);
  return retval;
}
int validate_rules(Plist *ulist, Plist *rlist, request_rec *r){
	Plist *tmp = NULL, *tmp2 = NULL;
	char *key = NULL, *val = NULL;
	char *rval = NULL, *tempstr = NULL, *tptr = NULL;
	int retval = 1;

	if(!ulist || !rlist) return retval;

	tmp = ulist;
	
	while(tmp){
		char *tuple;
		key = tmp->key;
		tmp2 = search_plist(rlist, key);
		if(tmp2)
			rval = tmp2->val;
		else
			rval = NULL;

		if(!rval){
			tmp = tmp->next;
			continue;
		}
		tempstr = strdup(rval);
		if(!tempstr) goto err_exit;
		tptr = tempstr;
		
		tuple = strsep(&tptr, ",");
		while(tuple != NULL){
			char *ptr = strchr(tuple, ':');
		  	char *rule_name, *rule_val;
		  	if(ptr){
			  	*ptr = '\0';
			  	rule_name = tuple;
			  	rule_val = ++ptr;
			  	if(!strcmp(rule_name, "avg_length")){
			  		if(!check_length(rule_val, tmp->val, r)){
			  			ap_rprintf(r, "<p>avg_length for %s failed!</p>", tmp->key);
			  			retval = 0;
			  			goto err_exit;
			  		}
			  	}
			  	else if(!strcmp(rule_name, "char_set")){
			  		if(!check_charset(rule_val, tmp->val, r)){
			  			ap_rprintf(r, "<p>char_set failed! for %s</p>", tmp->key);
			  			retval = 0;
			  			goto err_exit;
			  		}
			  	}
			  	else if(!strcmp(rule_name, "max_args")){
			  		if(!check_MaxArgs(ulist, rule_val, r)){
			  			ap_rprintf(r, "<p>Max_args failed! for %s</p>", tmp->key);
			  			retval = 0;
			  			goto err_exit;
			  		}
			  	}
		  	}
		  	tuple = strsep(&tptr, ",");
		}
		tmp = tmp->next;
		if(tempstr){
			free(tempstr);
			tempstr = NULL;
		}
	}

	err_exit:
	if(tempstr)  free(tempstr);
	return retval;
}
int check_rules(request_rec *r, char *buffer, int buflen){
  apr_file_t *fd;
  apr_fileperms_t perm = APR_OS_DEFAULT;
  char *rbuffer, *tmp_buf;
  int ch_sz = sizeof(char);
  int rbuflen = 0, rlen = 0;
  apr_status_t err = 0;
  int retval = 1;
  char *tuple, *key, *val;
  Plist *ulist = NULL, *rlist = NULL, *hulist = NULL, *hrlist = NULL;
  char filename[TMP_BUF_LEN];  
  if ((err = apr_initialize()) != APR_SUCCESS) 
  {
      char tmp_buf[TMP_BUF_LEN];
      ap_rprintf(r, "<p>ERROR APR_INIT: %s</p>", apr_strerror(err, tmp_buf, TMP_BUF_LEN));
      goto err_exit;
  }
  snprintf(filename, TMP_BUF_LEN, "%s%s_DUMP",LEARNER_DIR, r->uri);
  if((err = apr_file_open(&fd, filename, 
  	APR_FOPEN_READ, perm, r->pool)) 
  	!= APR_SUCCESS){
  	snprintf(filename, TMP_BUF_LEN, "%s/global.txt", LEARNER_DIR);
  	if((err = apr_file_open(&fd, filename, 
  		APR_FOPEN_READ, perm, r->pool)) != APR_SUCCESS){
	    char tmp_buf[TMP_BUF_LEN];
	    ap_rprintf(r, "<p>Error File open: %s</p>", apr_strerror(err, tmp_buf, TMP_BUF_LEN));
	    goto err_exit;
	}
  }

  tmp_buf = strdup(apr_punescape_url(r->pool, buffer, NULL, NULL, 0));
  if(!tmp_buf) goto err_exit;
  /*FIlling the user param list*/	
  tuple = strtok(tmp_buf, "&");
  while(tuple != NULL){
  	char *ptr = strchr(tuple, '=');
  	if(ptr){
	  	*ptr = '\0';
	  	key = tuple;
	  	val = ++ptr;
	  	insert_plist(&ulist, key, val, -1);
  	}
  	tuple = strtok(NULL, "&");
  }
  //print_plist(ulist, r, "User list");
  
  /*Filling the Rules param list*/
  rbuffer = (char *)malloc(sizeof(char)*MAX_REC_LEN);
  rbuflen = MAX_REC_LEN;
  rbuffer[0] = '\0';
  while(apr_file_gets(rbuffer, rbuflen, fd) == APR_SUCCESS){
  	char *ptr;
  	rlen = strlen(rbuffer);
  	if(rbuffer[rlen-1] == '\n')
  		rbuffer[rlen-1] = '\0';
  	ptr = strchr(rbuffer, '=');
  	if(ptr){
	  	*ptr = '\0';
	  	key = rbuffer;
	  	val = ++ptr;
	  	insert_plist(&rlist, key, val, -1);
  	}
  }
  //print_plist(rlist, r, "Rules List");

  /*Filling Headerlist*/
  hulist = fill_headers(r, r->headers_in);
  //print_plist(hulist, r, "Header List");
  
  /*Filling Dynamic rules from the file*/
  hrlist = fill_header_rules(r);
  //print_plist(hrlist, r, "Header Rules List");
  /*Check For the Dynamic Rules given in general.txt*/
  if(!check_dir_sql(hrlist, hulist, ulist, r)){
  	ap_rprintf(r, "<p>check_dir_sql failed!</p>");
  	retval = 0;
  	goto err_exit;
  }
  else{
  	//ap_rprintf(r, "<p>check_dir_sql success!</p>");
  }
  /*Check rules per parameter*/
  if(!validate_rules(ulist, rlist, r)){
  	ap_rprintf(r, "<p>validate_rules failed!</p>");
  	retval = 0;
  	goto err_exit;
  }
  else{
  	//ap_rprintf(r, "<p>validate_rules success!</p>");
  }
  
  /*Clean UP*/
  err_exit:
  if(retval == 0){
  	print_plist(ulist, r, "User list");
  	print_plist(rlist, r, "Rules List");
  	print_plist(hulist, r, "Header List");
  	print_plist(hrlist, r, "Header Rules List");
  }
  /*UNLOCK THE LOG FILE*/
  //apr_file_unlock(fd);
  destroy_plist(&ulist);
  destroy_plist(&rlist);
  destroy_plist(&hulist);
  destroy_plist(&hrlist);
  if(tmp_buf) 	free(tmp_buf);
  if(rbuffer)	free(rbuffer);
  if(fd) 		apr_file_close(fd);
  return retval;
}

int util_read(request_rec *r, char *rbuf, int buflen)
{
    int rc;

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK) {
        //ap_rprintf(r, "<p>Client block err</p>");
        return rc;

    }

    if (ap_should_client_block(r)) {
        char argsbuffer[MAX_REC_LEN];
        int rsize, len_read, rpos=0;
        long length = buflen;

        while ((len_read = ap_get_client_block(r, argsbuffer,
					sizeof(argsbuffer))) > 0) {
            if ((rpos + len_read) > length) {
                rsize = length - rpos;
            } else {
                rsize = len_read;
            }

            memcpy(rbuf + rpos, argsbuffer, rsize);
            rpos += rsize;
        }
    }

    return rc;
}

int read_post(request_rec *r, char*buf, int buflen)
{
    const char *type;
    int rc = OK;
    
    if ((rc = util_read(r, buf, buflen)) != OK) {
    	//ap_rprintf(r, "<p>Post Data %s</p>", data);
        return rc;
    }
    //ap_rprintf(r, "<p>Post Data %s</p>", buf);
    return OK;
}