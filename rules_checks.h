#include <ctype.h>
#include <errno.h>

int check_charset(char *rule_val, char *u_value, request_rec *r)
{
  /*Character Set definition
    1 - Alphabets only
    2 - Numbers only
    3 - Alphanumeric
    7 - Alphanumeric with special characters
  */
  int a_len=0, n_len=0, ansp_len=0;
  size_t type = -1;
  char *tempstr, *tptr = NULL, *endptr = NULL;
  size_t rule_len = strtol(rule_val, &endptr, 10);
  int retval = 0;
  if (!endptr){
  	retval = 0;
  	goto err_exit;
  }

  tptr = strdup(u_value);
  tempstr = tptr;
  if(!tempstr){
   retval = 0;
   goto err_exit;
  }
  
  while(*tempstr != '\0')
  {
    if (isdigit(*tempstr))
      n_len++; 
    else if(isalpha(*tempstr))
      a_len++;
    else
      ansp_len++;
    tempstr++;
  }
  if (a_len != 0 || n_len != 0 || ansp_len != 0){
     type = 7;
     if(rule_len == type){
  		retval = 1;
  		goto err_exit;
  	}
  }
  if (a_len != 0 || n_len != 0){
     type = 3;
  	 if(rule_len == type){
  		retval = 1;
  		goto err_exit;
  	}
  }
  if (n_len != 0){
     type = 2;
  	 if(rule_len == type){
  		retval = 1;
  		goto err_exit;
  	}
  }
  if (a_len != 0){
     type = 1;
  	 if(rule_len == type){
  		retval = 1;
  		goto err_exit;
  	}
  }
  //printf("a_len:%d, n_len:%d, ansp_len:%d\n", a_len, n_len, ansp_len);
  err_exit:
  if(retval == 0)
  	ap_rprintf(r, "<p><b>ERR:</b> Type obtained:%d Given Type:%d</p>", type, rule_len);
  if(tptr)		free(tptr);
  
  return retval; 
}

int check_MaxArgs(struct Plist *ulist, char *rule_val, request_rec *r)
{
  long int ulength = 0;
  struct Plist *temp = ulist;
  char *endptr = NULL;
  long int r_maxargs = strtol(rule_val,&endptr,10);
  if(!endptr) //conversion not possible
    return 0;
  
  ulength = len_plist(ulist);
  if(ulength <= r_maxargs)
    return 1; //max args in user list matching to the value in rule maxargs
  else{
    ap_rprintf(r, "<p><b>ERR:</b>Ulength:%ld maxargs:%ld</p>", ulength, r_maxargs);
    return 0;
  }
}

int check_length(char *rule_val, char *u_value, request_rec *r)
{
  char *token;
  char *tempstr = strdup(rule_val);
  size_t min_val, max_val;
  size_t u_length = strlen(u_value);
  int retval = 0;
  char* endptr = NULL;

  if(!tempstr) goto err_exit;
  token = strtok(tempstr, "?");
  min_val = strtol(token, &endptr, 10);
  if(!endptr)
     goto err_exit;
  token = strtok(NULL,"?");
  max_val = strtol(token, &endptr, 10);
  if (!endptr)
     goto err_exit;
  if ((u_length >= min_val) && (u_length <= max_val))
      retval = 1;
  else
  	ap_rprintf(r, "<p><b>ERR:</b>ulength:%d, min:%d, max:%d</p>", u_length, min_val, max_val);

  err_exit:
  if(tempstr)	free(tempstr);
  return retval;
}

int check_dir_sql(Plist *hrlist, Plist *hulist, Plist *ulist, request_rec *r){
	Plist *tmp = hrlist, *tmp2 = NULL;
	int retval = 1;
	char *ptr1= NULL, *ptr2 = NULL, *tptr = NULL;

	while(tmp){

		if(tmp->type == 0){
			tmp2 = search_plist(hulist, tmp->key);
			if(!tmp2){
				tmp = tmp->next;
				continue;
			}
			ptr1 = strdup(tmp->val);//strdup(ap_escape_html(r->pool,tmp->val));
			ptr2 = strdup(tmp2->val);//strdup(ap_escape_html(r->pool,tmp2->val));
			if(ptr1 = strstr(ptr1, "&lt;")){
				ptr1 += 4;
				if(tptr = strstr(ptr1, "&gt;")){
					*tptr = '\0';
				}
				if(ptr2 = strstr(ptr2, "&lt;"))
					ptr2 += 4;
				else
					ptr2 = tmp2->val;
			}
			else{
				ptr1 = tmp->val;
			}
			//ap_rprintf(r, "<p><b>ERR:</b> ptr2:%s ptr1:%s strstr:%s</p>", ptr2, ptr1, strstr(ptr2, ptr1));
			if(strcasestr(ptr2, ptr1)){
				ap_rprintf(r, "<p><b>ERR:</b> Request contains keyword:%s</p>", tmp->val);
				retval = 0;
				goto err_exit;
			}

		}
		else if(tmp->type == 1){
			if(!strcmp("*", tmp->key)){
				Plist *utmp = ulist;
				while(utmp){
					if(strcasestr(utmp->val, tmp->val)){
						ap_rprintf(r, "<p><b>ERR:</b> Request contains keyword:%s</p>", tmp->val);
						retval = 0;
						goto err_exit;
					}
					utmp = utmp->next;
				}
			}
			else{
				Plist *utmp = search_plist(ulist, tmp->key);
				if(utmp){
					if(strcasestr(utmp->val, tmp->val)){
						ap_rprintf(r, "<p><b>ERR:</b> Request contains keyword:%s</p>", tmp->val);
						retval = 0;
						goto err_exit;
					}
				}
			}
		}
		tmp = tmp->next;
	}

	err_exit:
	return retval;
}
