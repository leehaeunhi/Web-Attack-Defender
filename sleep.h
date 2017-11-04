#ifndef __VI_SLEEP_H
#define __VI_SLEEP_H
 
#ifdef WIN32
#include <windows.h>
#define vi_sleep(x) Sleep((x)*1000)
#else
#include <unistd.h>
#define vi_sleep(x) sleep(x)
#endif
 
#endif /* __VI_SLEEP_H */

extern void setLogline(char * buf);
extern void analyze (GtkNotebook *notebook,
         GtkWidget   *page,
         guint        page_num,
         gpointer     user_data);
 
GtkWidget *sw;
GtkWidget *sw_unique_visitors;
GtkWidget *sw_web_attacks;
GtkWidget *sw_total_logs;
 
GtkWidget *list;
GtkWidget *list_unique_visitors;
GtkWidget *list_web_attacks;
GtkWidget *list_total_logs;
 
GtkListStore *store;
GtkListStore *store2;
GtkListStore *store_web_attacks;
GtkListStore *store_total_logs;
 
GtkTreeIter iter;
GtkTreeIter iter2;
GtkTreeIter iter_web_attacks;
GtkTreeIter iter_total_logs;   
GtkTextMark *mark;
 
long ddos;
long sql_injection;
long rfi_lfi;
long webshell;
long log_count;
long sum_logs;
float average;
float before_median;
time_t before_median_time;
float from_before_median_count;
float median;
int is_ddos;
 
time_t startTime;
pthread_mutex_t mutex; 
 
typedef struct byIP {
    char ip[16];
    int count;
    long today;
    int block;   
    time_t startTime;
    struct byIP *nextIP;
}byIP;
 
byIP *head;
 
enum {
    COL_IP,
    COL_LOGICAL_USERNAME,
    COL_USER,
    COL_TIME,
    COL_REQUEST,
    COL_STATUS,
    COL_BYTES,
    COLOR,
    N_COLUMNS
};
 
enum {
    COL_RANKING,
    COL_HOST,
    COL_COUNT,
    COL_VALUE_PROGRESS_VISIBLE,
    COL_VALUE_PROGRESS_VALUE,
    COL_VALUE_PROGRESS_TEXT,
    NUM_COLUMNS
};
 
enum {
    COL_ATTACK_NAME,
    COL_ATTACK_COUNT,
    COL_ATTACK_PROGRESS_VISIBLE,
    COL_ATTACK_PROGRESS_VALUE,
    COL_ATTACK_PROGRESS_TEXT,
    N_ATTACK_COLUMNS
};
 
enum {
    COL_TOTAL_COUNT,
    N_TOTAL_COLUMNS
};  

