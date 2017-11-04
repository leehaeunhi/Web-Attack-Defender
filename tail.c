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
/*
typedef struct byIP {
    char ip[16];
    int count;
    long today;   
    time_t startTime;
    struct byIP *nextIP;
}byIP;
*/
static count;
 
//int log_count = 0;
int ip_count = 0;
 
//byIP *head = NULL;
byIP *current = NULL;

int last_byte = 0;
 
//GtkListStore *store;
//GtkListStore *store2;

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
            //printf("\n>SQL Injection\n");        // SQL 인젝션 경고
            free(text);
            return 1;
        } else if (strstr(tok, "%00")||strstr(tok,"http")||strstr(tok, "/"))
        {
            rfi_lfi++;
            //printf("\n>RFI\n");        // RFI 경고
            free(text);
            return 2;
        } else {
            free(text);
            return 0;
        }
    } else {
        //printf("정상\n");
        free(text);
        return 0;
    }
   
    //free(text);
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
/*    }else if (strstr(text, blacklist)) {
        return 1;
*/    }else {
        free(text);
        return 0;
    }


}

 
/* function for parsing the date of log
 * date format: day/month/year:h:m:s */
 /*
static char * parseTime(char * times)
{
    char * text = (char *)malloc((strlen(times)+1)*sizeof(char));
    strcpy(text, times);
 
    char * day;        char * month;
    char * year;        char * hour;
    char * min;        char * sec;
 
    int month_num = 0;
       
        if(text == NULL) {
            printf("parseTime text error");
            exit(1);
        }
 
//    strcat(time, "\0");
//    printf("%s", time);
 
    day     = strtok(times, "/");
    month     = strtok(NULL, "/");
    year     = strtok(NULL, ":");
    hour     = strtok(NULL, ":");
    min     = strtok(NULL, ":");
    sec     = strtok(NULL, " ");
   
    if(!strcmp(month, "Jan"))
                month_num = 1;
    else if(!strcmp(month, "Feb"))
                month_num = 2;
    else if(!strcmp(month, "Mar"))
                month_num = 3;
    else if(!strcmp(month, "Apr"))
                month_num = 4;
    else if(!strcmp(month, "May"))
                month_num = 5;
    else if(!strcmp(month, "Jun"))
                month_num = 6;
    else if(!strcmp(month, "Jul"))
                month_num = 7;
    else if(!strcmp(month, "Aug"))
                month_num = 8;
    else if(!strcmp(month, "Sep"))
                month_num = 9;
    else if(!strcmp(month, "Oct"))
                month_num = 10;
    else if(!strcmp(month, "Nov"))
                month_num = 11;
    else if(!strcmp(month, "Dec"))
        month_num = 12;
 
    sprintf(text,"%s/%d/%s %s:%s:%s\t",year,month_num,day,hour,min,sec);
//    sprintf(text,"%s:%s:%s",hour,min,sec);
    printf("%s", text);
 
    return text;
}
 */
/* function for parsing the status code of log*/
 
static void parseCode(char * code)
{
    int codenum;
    if(code == NULL) {
        printf("parseCode error");
        exit(1);
    }
    codenum = atoi(code);
   
    // 범위만 처리한다면, if문을
    // 모든 코드를 다 처리한다면, switch문 쓰는게 좋을듯
   
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
 
//    printf("%d",codenum);
}
 
/*
struct byIP* create_byIP(char *host, time_t t)
{
    struct byIP* new_byIP = (struct byIP*)malloc(sizeof(struct byIP));
   
    strcpy(new_byIP->ip, host);
    new_byIP->count = 1;
    new_byIP->today = 1;
    new_byIP->startTime = t;
    new_byIP->nextIP = NULL;
 
    return new_byIP;
}*/
 
void insert_byIP(char *host, time_t t)
{
    //struct byIP* after = current->nextIP;
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
    //new_byIP->nextIP = after;
     new_byIP->nextIP = NULL;

    /* current 는 이제 newNode 를 가리키게 된다 */
    current->nextIP = new_byIP;
 
    current = new_byIP;
    //free(new_byIP);
}
 
 
struct byIP* search_byIP(char *ip) 
{
    byIP *temp = head;
    
    if(ip == NULL) {
        printf("search_byIP error\n");
        exit(1);
    }
 
    while(temp != NULL) {
        //printf("1\n");
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
        //head = create_byIP(host, t1);
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
    
        //printf("> ip %s : %d\n", current->ip, current->count);
    
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
        //printf("> ip %s : %d\n", temp->ip, temp->count);
        return;
    }
   
    // new IP
    insert_byIP(host, t1);   
    //printf("> ip %s : %d\n", current->ip, current->count);
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
//    trash = strtok(NULL, "\n");
 
    //printf("\n%s\t", ip);
    //printf("%s\t", luser);
    //printf("%s\t", user);
//    printf("%s\n", time);
//    parseTime(times);
    //times = parseTime(times);


//    strcat(time, "\0");
//    printf("%s", time);

/*    text         = (char *)malloc((strlen(times)+1)*sizeof(char));
         
        if(text == NULL) {
            printf("setLogLine text error");
            exit(1);
        }
 
    
    day     = strtok(times, "/");
    month     = strtok(NULL, "/");
    year     = strtok(NULL, ":");
    hour     = strtok(NULL, ":");
    min     = strtok(NULL, ":");
    sec     = strtok(NULL, " ");
   
    sprintf(text,"%s/%s/%s %s:%s:%s\t",year,month,day,hour,min,sec);
//    sprintf(text,"%s:%s:%s",hour,min,sec);
    printf("%s", text);*/



//    printf("%s\n", times);
    //printf("%s\t", req);
    //printf("%s: ", code);
    //parseCode(code);
    //printf("%s\n", bytes);

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
   
//        system("./getflood.sh");
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
//        system("./rfi.sh");
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
//        system("./rfi.sh");
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
        //free(text);
    //fflush(stdout);
    gtk_scrolled_window_set_vadjustment(GTK_SCROLLED_WINDOW(sw), 0);   
    pthread_mutex_unlock(&mutex);
    //printf("unlocked(%08x :: %d)..!\n", (int)ptid, lock_ret);
}