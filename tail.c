#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <glib.h>
#include <time.h>
#include <string.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <pthread.h>
#include "sleep.h"
 
#define VI_FILENAMES_MAX 1024
 
typedef struct logformat {
    char * ip;
    char * luser;
    char * user;
    char * times;
    char * req;
    char * code;
    char * bytes;
}logformat;

static count;
 
int ip_count = 0;
 
byIP *current = NULL;

int last_byte = 0;

void beep(void);

void beep(void)
{
    printf("\a");
}

static int parseReq(char * req)
{
    char * text;
    char * tok;
   

        if(req == NULL) {
            printf("parseReq erre\n");
            exit(1);
        }

         text    = (char *)malloc((strlen(req)+1)*sizeof(char));
   
        if(text == NULL) {
            printf("parseReq text erre\n");
            exit(1);
        }
strcpy(text, req);
 
    if (strstr(text, "?")) {
        strtok(text, "?");
        tok = strtok(NULL, " ");
 
        if (strstr(tok, "'")||strstr(tok, ")")||strstr(tok, "%20")||strstr(tok, "%27")||strstr(tok, "+")||strstr(tok, "UNION"))
        {
            sql_injection++;
            free(text);
            return 1;
        } else if (strstr(tok, "%00")||strstr(tok,"http")||strstr(tok, "/"))
        {
            rfi_lfi++;
            free(text);
            return 2;
        } else {
            free(text);
            return 0;
        }
    } else {
        free(text);
        return 0;
    }
}

static int parseBytes(char * req, char * bytes)
{
    char * text;
    int     ibytes    = atoi(bytes);
    int     diff     = abs(last_byte-ibytes);
    char * tok;

    text    = (char *)malloc((strlen(req)+1)*sizeof(char));
    if(text == NULL) {
        printf("parseBytes text err\n");
        exit(1);
    }

    last_byte = ibytes;

    strcpy(text, req);

    if(diff >= 10000) {
        strtok(text, "/");
        tok = strtok(NULL, " ");
        webshell++;
        free(text);
        return 1;
    }else {
        free(text);
        return 0;
    }


}

 
/* function for parsing the status code of log*/
static void parseCode(char * code)
{
    int codenum;
    if(code == NULL) {
        printf("parseCode error");
        exit(1);
    }
    codenum = atoi(code);

    if(codenum < 200)
    {
        printf("Informatioinal\t");
    }else if(codenum < 300)
    {
        printf("Success\t");
    }else if(codenum < 400)
    {
        printf("Redirection\t");
    }else if(codenum < 500)
    {
        printf("Client Error\t");
    }else if(codenum < 600)
    {
        printf("Server Error\t");
    }
 }
 
void insert_byIP(char *host, time_t t)
{
    struct byIP* after;       
   
    struct byIP* new_byIP = (struct byIP *)malloc(sizeof(struct byIP));
    
    if(host == NULL) {
        printf("insert_byIp host error\n");
        exit(1);
    }

    if(new_byIP == NULL) {
        printf("insert_byIP new_byIP error\n");
        exit(1);
    }
 
    /* 새 노드에 값을 넣어준다. */
    strcpy(new_byIP->ip, host);
    new_byIP->count = 1;
    new_byIP->today = 1;
    new_byIP->startTime = t;
     new_byIP->nextIP = NULL;

    /* current 는 이제 newNode 를 가리키게 된다 */
    current->nextIP = new_byIP;
 
    current = new_byIP;
}
 
 
struct byIP* search_byIP(char *ip) 
{
    byIP *temp = head;
    
    if(ip == NULL) {
        printf("search_byIP error\n");
        exit(1);
    }
 
    while(temp != NULL) {
        if(!strcmp(ip, temp->ip)) {            
            return temp;
        }
           temp = temp->nextIP;
    }
    
    return NULL;
}
 
 
 
/* function for saving the contents of buf */
/* Tried to give 'logformat * lf' as a parameter.
 * It works at first,
 * but it occured segmentation fault at next time */
void count_ip(char * host)
{
    int i;
    long gap;
    time_t t1, t2;   
    struct byIP *temp;
    struct byIP* new_byIP;
        
    time(&t1);
     
    if(host == NULL) {
        printf("count_ip host error\n");
        exit(1);
    }
       
    // first IP
    if(ip_count == 0) {
        new_byIP = (struct byIP*)malloc(sizeof(struct byIP));
           if(new_byIP == NULL) {
               printf("count_ip new_byIP error\n");
            exit(1);
        }
        
        strcpy(new_byIP->ip, host);
   
        new_byIP->count = 1;
        new_byIP->today = 1;
        new_byIP->startTime = t1;
        new_byIP->nextIP = NULL;
         
        head = new_byIP;   
        current = head;
        
        ip_count++;

        return;
    }
 
    // old IP
    if(temp = search_byIP(host)) {
        gap = (long)(t1 - temp->startTime);

        if(temp == NULL) {
            printf("count_ip error\n");
            exit(1);
        }
           
        temp->count++;
        temp->today++;
        return;
    }
   
    // new IP
    insert_byIP(host, t1);   
    ip_count++;
    return;
}
 
void setLogline(char * buf)
{
    char * ip;        char * luser;
    char * user;      char * times;
    char * req;       char * code;
    char * bytes;     char * trash;
  
    char * day;       char * month;
    char * year;      char * hour;
    char * min;       char * sec;
    char * text;

    int wait = 1;
    int a;
    time_t t;
    int is_rfi=0;
 
    log_count++;
    from_before_median_count++;

    sum_logs = log_count;
   
    average = (float)log_count / (float)(t-startTime);
 
    if(buf == NULL) {
        printf("setLogline buf \n");
        exit(1);
    }
   
    ip = strtok(buf, " ");
    if(ip == NULL) return;
 
    luser = strtok(NULL, " ");
    if(luser == NULL) return;
 
    user = strtok(NULL, "[");
    if(user == NULL) return;
 
    times = strtok(NULL, "+");
    if(times == NULL) return;
   
    trash = strtok(NULL, "\"");
    if(trash == NULL) return;   
   
    req = strtok(NULL, "\"");
    if(req == NULL) return;
 
    code = strtok(NULL, "\" ");
    if(code == NULL) return;
 
    bytes = strtok(NULL, "\"");
    if(bytes == NULL) return;

    count_ip(ip);
    is_rfi = parseReq(req);
 
    if(is_ddos == 1) {
        ddos++;
        store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
        gtk_list_store_prepend(store, &iter);
        gtk_list_store_set(store, &iter,
                   COL_IP, ip,
                   COL_LOGICAL_USERNAME, luser,
                   COL_USER, user,
                   COL_TIME, times,
                   COL_REQUEST, req,
                   COL_STATUS, code,
                   COL_BYTES, bytes,
                   COLOR, "Crimson",
                   -1);
    beep();
   
    } else if(is_rfi == 1) {
        store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
        gtk_list_store_prepend(store, &iter);
        gtk_list_store_set(store, &iter,
                   COL_IP, ip,
                   COL_LOGICAL_USERNAME, luser,
                   COL_USER, user,
                   COL_TIME, times,
                   COL_REQUEST, req,
                   COL_STATUS, code,
                   COL_BYTES, bytes,
                   COLOR, "Sky Blue",
                   -1);
    beep();
    } else if(is_rfi == 2) {
        store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
        gtk_list_store_prepend(store, &iter);
        gtk_list_store_set(store, &iter,
                   COL_IP, ip,
                   COL_LOGICAL_USERNAME, luser,
                   COL_USER, user,
                   COL_TIME, times,
                   COL_REQUEST, req,
                   COL_STATUS, code,
                   COL_BYTES, bytes,
                   COLOR, "Gold",
                   -1);
    beep();
    } else if(parseBytes(req, bytes) == 1) {
        store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
        gtk_list_store_prepend(store, &iter);
        gtk_list_store_set(store, &iter,
                   COL_IP, ip,
                   COL_LOGICAL_USERNAME, luser,
                   COL_USER, user,
                   COL_TIME, times,
                   COL_REQUEST, req,
                   COL_STATUS, code,
                   COL_BYTES, bytes,
                   COLOR, "Plum",
                   -1);
    }else {
        store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list)));
        gtk_list_store_prepend(store, &iter);
        gtk_list_store_set(store, &iter,
                   COL_IP, ip,
                   COL_LOGICAL_USERNAME, luser,
                   COL_USER, user,
                   COL_TIME, times,
                   COL_REQUEST, req,
                   COL_STATUS, code,
                   COL_BYTES, bytes,
                   COLOR, "White",
                   -1);
    }
    gtk_scrolled_window_set_vadjustment(GTK_SCROLLED_WINDOW(sw), 0);   
    pthread_mutex_unlock(&mutex);
}