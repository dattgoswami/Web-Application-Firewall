
typedef struct Plist{
	char *key;
	char *val;
	int type;
	struct Plist *next;
}Plist;

void insert_plist(Plist **head, char *key, char *val, int req_type){
	Plist *tmp = NULL;

	if(!head) return;
	
	if(!*head){
		*head = (Plist *)malloc(sizeof(Plist));
		if(!*head) return;
		(*head)->key = strdup(key);//ap_escape_html(pool, key);
		(*head)->val = strdup(val);//ap_escape_html(pool, val);
		(*head)->type = req_type;
		(*head)->next = NULL;
		return;
	}
	else{
		tmp = *head;
		*head = (Plist *)malloc(sizeof(Plist));
		if(!*head){
			*head = tmp;
			return;
		}
		(*head)->key = strdup(key);//ap_escape_html(pool, key);
		(*head)->val = strdup(val);//ap_escape_html(pool, val);
		(*head)->type = req_type;
		(*head)->next = tmp;
		return;
	}
}
Plist* search_plist(Plist *head, char *key){
	Plist *tmp = NULL;
	if(!head) return NULL;

	tmp = head;
	while(tmp){
		if(!strcmp(tmp->key, key)){
			return tmp;
		}
		tmp = tmp->next;
	}
	return NULL;
}
void destroy_plist(Plist **head){
	Plist *tmp = NULL, *tmp2 = NULL;
	if(!head || !*head) return;

	tmp = *head;
	while(tmp){
		tmp2 = tmp->next;
		if(tmp->key)	free(tmp->key);
		if(tmp->val)	free(tmp->val);
		free(tmp);
		tmp = tmp2;
	}
	*head = NULL;
	return;
}

void print_plist(Plist *head, request_rec *r, char *str){
	Plist *tmp = head;
	if(!head) return;
	ap_rprintf(r, "<p>");
	ap_rprintf(r, "--------------------------------------<br/>");
	ap_rprintf(r, "Printing Plist %s<br/>", str);
	ap_rprintf(r, "--------------------------------------<br/>");
	tmp = head;
	while(tmp){
		ap_rprintf(r, "KEY:%s  VAL:%s<br/>", tmp->key, tmp->val);
		tmp = tmp->next;
	}
	ap_rprintf(r, "</p>");
	return;
}

int len_plist(Plist *head){
	int count = 0;
	
	while(head){
		count++;
		head = head->next;
	}
	return count;
}