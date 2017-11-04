#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <time.h>
#include <string.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <pthread.h>
#include <math.h>
#include "sleep.h"
#include <sys/inotify.h>
#include <sys/types.h>

#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE +16))

#define TAILOUT_BUFLEN 4096

int offset = 0;
int init_len = -1;

GtkWidget *window;
GtkWidget *notebook;
GtkCellRenderer    *renderer;

GtkTreeViewColumn  *column;
GtkTreeViewColumn  *column2;
GtkTreeViewColumn  *column_web_attacks;
GtkTreeViewColumn  *column_total_logs;

char *filename;


void init_list(GtkWidget *list)
{
    GtkCellRenderer     *renderer;
    GtkCellRenderer     *renderer2;
    GtkCellRenderer     *renderer_web_attacks;
    GtkCellRenderer     *renderer_total;

    // log viewer
    store = gtk_list_store_new(N_COLUMNS,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,
                               G_TYPE_STRING,

                               G_TYPE_STRING
                               );

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("CLIENT IP", renderer, "text", COL_IP, NULL);
    gtk_tree_view_column_set_sizing (column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_column_add_attribute(column, renderer, "background", COLOR);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("LOGICAL USERNAME", renderer, "text", COL_LOGICAL_USERNAME, NULL);
    gtk_tree_view_column_set_sizing (column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_column_add_attribute(column, renderer, "background", COLOR);
      gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("USER", renderer, "text", COL_USER, NULL);
    gtk_tree_view_column_set_sizing (column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_column_add_attribute(column, renderer, "background", COLOR);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("TIME", renderer, "text", COL_TIME, NULL);
    gtk_tree_view_column_set_sizing (column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_column_add_attribute(column, renderer, "background", COLOR);
      gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("REQUEST", renderer, "text", COL_REQUEST, NULL);
    gtk_tree_view_column_set_sizing (column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_column_add_attribute(column, renderer, "background", COLOR);
       gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("STATUS", renderer, "text", COL_STATUS, NULL);
    gtk_tree_view_column_set_sizing (column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_column_add_attribute(column, renderer, "background", COLOR);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);

    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("BYTES", renderer, "text", COL_BYTES, NULL);
    gtk_tree_view_column_set_sizing (column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_column_add_attribute(column, renderer, "background", COLOR);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list), column);

    gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(store));

    g_object_unref(store);
    
 
      // log analyzer - unique visitors
    store2 = gtk_list_store_new(NUM_COLUMNS,
                                G_TYPE_UINT,
                                G_TYPE_STRING,
                                G_TYPE_UINT,
                                G_TYPE_BOOLEAN,
                                 G_TYPE_INT,
                                 G_TYPE_STRING
                                );
                          
    renderer2 = gtk_cell_renderer_text_new();
    column2 = gtk_tree_view_column_new_with_attributes("ORDER", renderer2, "text", COL_RANKING, NULL);
    gtk_tree_view_column_set_sizing (column2, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_column_set_sort_column_id (column2, COL_RANKING);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list_unique_visitors), column2);
 
    renderer2 = gtk_cell_renderer_text_new();
    column2 = gtk_tree_view_column_new_with_attributes("CLIENT IP", renderer2, "text", COL_HOST, NULL);
    gtk_tree_view_column_set_sizing (column2, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list_unique_visitors), column2);
 
    renderer2 = gtk_cell_renderer_text_new();
    column2 = gtk_tree_view_column_new_with_attributes("COUNT", renderer2, "text", COL_COUNT, NULL);
    gtk_tree_view_column_set_sizing (column2, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list_unique_visitors), column2);

    renderer2 = gtk_cell_renderer_progress_new();
    column2 = gtk_tree_view_column_new();
    gtk_tree_view_column_set_title(column2, "GRAPH");
    gtk_tree_view_column_pack_start(column2, renderer2, TRUE);
    gtk_tree_view_column_set_attributes(column2, renderer2,
                "visible", COL_VALUE_PROGRESS_VISIBLE,
                "value", COL_VALUE_PROGRESS_VALUE,
                "text", COL_VALUE_PROGRESS_TEXT, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list_unique_visitors), column2);
 
    gtk_tree_view_set_model(GTK_TREE_VIEW(list_unique_visitors), GTK_TREE_MODEL(store2));

    g_object_unref(store2);


    // log analyzer - web attacks
    store_web_attacks = gtk_list_store_new(N_ATTACK_COLUMNS,
                                           G_TYPE_STRING,
                                           G_TYPE_UINT,
                                                G_TYPE_BOOLEAN,
                                             G_TYPE_INT,
                                             G_TYPE_STRING
                                           );
                           
    renderer_web_attacks = gtk_cell_renderer_text_new();
    column_web_attacks = gtk_tree_view_column_new_with_attributes("ATTACK", renderer_web_attacks, "text", COL_ATTACK_NAME, NULL);
    gtk_tree_view_column_set_sizing (column_web_attacks, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list_web_attacks), column_web_attacks);
 
    renderer_web_attacks = gtk_cell_renderer_text_new();
    column_web_attacks = gtk_tree_view_column_new_with_attributes("COUNT", renderer_web_attacks, "text", COL_ATTACK_COUNT, NULL);
    gtk_tree_view_column_set_sizing (column_web_attacks, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list_web_attacks), column_web_attacks);

    renderer_web_attacks = gtk_cell_renderer_progress_new();
    column_web_attacks = gtk_tree_view_column_new();
    gtk_tree_view_column_set_title(column_web_attacks, "GRAPH");
    gtk_tree_view_column_pack_start(column_web_attacks, renderer_web_attacks, TRUE);
    gtk_tree_view_column_set_attributes(column_web_attacks, renderer_web_attacks,
                "visible", COL_ATTACK_PROGRESS_VISIBLE,
                "value", COL_ATTACK_PROGRESS_VALUE,
                "text", COL_ATTACK_PROGRESS_TEXT, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list_web_attacks), column_web_attacks);
 
    gtk_tree_view_set_model(GTK_TREE_VIEW(list_web_attacks), GTK_TREE_MODEL(store_web_attacks));

    g_object_unref(store_web_attacks);


    // log analyzer - total
    store_total_logs = gtk_list_store_new(N_TOTAL_COLUMNS,
                                           G_TYPE_UINT
                                                                       );
                           
    renderer_total = gtk_cell_renderer_text_new();
    column_total_logs = gtk_tree_view_column_new_with_attributes("TOTAL", renderer_total, "text", COL_TOTAL_COUNT, NULL);
    gtk_tree_view_column_set_sizing (column_total_logs, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(GTK_TREE_VIEW(list_total_logs), column_total_logs);

 
    gtk_tree_view_set_model(GTK_TREE_VIEW(list_total_logs), GTK_TREE_MODEL(store_total_logs));

    g_object_unref(store_total_logs);
}

int check_block_ip(char *ip) {
    byIP *temp = head;

    while(temp != NULL) {
        if(!strcmp(ip, temp->ip)) {
            if(temp->block == 1) {
                temp->block = 0;
                return 1;
            }
            else {                       
                temp->block = 1;
                return 0;
            }
        }
        temp = temp->nextIP;
    }
    return 0;
}

void
block_ip (GtkTreeView        *treeview,
          GtkTreePath        *path,
          GtkTreeViewColumn  *col,
          gpointer            userdata)
{
    GtkTreeModel *model;
    GtkTreeIter   iter_selected;
    char buf[500];
 
    model = gtk_tree_view_get_model(treeview);

    if (gtk_tree_model_get_iter(model, &iter_selected, path)) {
        gchar *name;

           gtk_tree_model_get(model, &iter_selected, COL_IP, &name, -1);
 
        if(check_block_ip(name) == 1) {
            sprintf(buf, "iptables -D INPUT -s %s -j DROP", name);
            system(buf);
            gtk_list_store_set(store, &iter_selected,
                   COLOR, "White",
                   -1);
        }   
        else {
            sprintf(buf, "iptables -A INPUT -s %s -j DROP", name);
            system(buf);
            gtk_list_store_set(store, &iter_selected, COLOR, "Grey", -1);
        }
 
           g_free(name);
    }

}

void gui()
{
    GtkWidget *grid;
    GtkWidget *vbox;
    GtkWidget *vbox_analyzer;
    GtkWidget *frame;
    GtkWidget *label;
    GtkWidget *label2;
    GtkWidget *label_unique_visitors;
    GtkWidget *label_web_attacks;
    GtkWidget *label_total_logs;

    char unique_visitors[32];
    char web_attacks[32];
    char total_logs[32];
 

    // window
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "WAD Viewer");
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_container_set_border_width(GTK_CONTAINER (window), 10);
    gtk_widget_set_size_request(window, 1000, 500);
    gtk_window_set_resizable (GTK_WINDOW(window), TRUE);


    // log viewer
    sw = gtk_scrolled_window_new(NULL, NULL);
    list = gtk_tree_view_new();
    gtk_container_add(GTK_CONTAINER(sw), list);
 
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw), GTK_POLICY_ALWAYS, GTK_POLICY_ALWAYS);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw), GTK_SHADOW_ETCHED_IN);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(list), TRUE);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_start(GTK_BOX(vbox), sw, TRUE, TRUE, 5);
 
 
    // log analyzer - unique visitors per day
    sprintf(unique_visitors, "Unique Visitors per day");
    label_unique_visitors = gtk_label_new (unique_visitors);

    sw_unique_visitors = gtk_scrolled_window_new(NULL, NULL);
    list_unique_visitors = gtk_tree_view_new();
    gtk_container_add(GTK_CONTAINER(sw_unique_visitors), list_unique_visitors);
 
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw_unique_visitors), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw_unique_visitors), GTK_SHADOW_ETCHED_IN);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(list_unique_visitors), TRUE);
 
    // log analyzer - web attacks per day
    sprintf(web_attacks, "Web Attacks per day");
    label_web_attacks = gtk_label_new (web_attacks);

    sw_web_attacks = gtk_scrolled_window_new(NULL, NULL);
    list_web_attacks = gtk_tree_view_new();
    gtk_container_add(GTK_CONTAINER(sw_web_attacks), list_web_attacks);
 
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw_web_attacks), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw_web_attacks), GTK_SHADOW_ETCHED_IN);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(list_web_attacks), TRUE);

    // log analyzer - total amount of logs
    sprintf(total_logs, "Total Amount of Logs");
    label_total_logs = gtk_label_new (total_logs);

    sw_total_logs = gtk_scrolled_window_new(NULL, NULL);
    list_total_logs = gtk_tree_view_new();
    gtk_container_add(GTK_CONTAINER(sw_total_logs), list_total_logs);
 
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw_total_logs), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw_total_logs), GTK_SHADOW_ETCHED_IN);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(list_total_logs), TRUE);

    //attach vbox
    vbox_analyzer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);

    gtk_container_add (GTK_CONTAINER (vbox_analyzer), label_unique_visitors);
    gtk_box_pack_start(GTK_BOX(vbox_analyzer), sw_unique_visitors, TRUE, TRUE, 5);

    gtk_container_add (GTK_CONTAINER (vbox_analyzer), label_web_attacks);
    gtk_box_pack_start(GTK_BOX(vbox_analyzer), sw_web_attacks, TRUE, TRUE, 5);

    gtk_container_add (GTK_CONTAINER (vbox_analyzer), label_total_logs);
    gtk_box_pack_end(GTK_BOX(vbox_analyzer), sw_total_logs, TRUE, TRUE, 5);
 
 
    // notebook
    grid = gtk_grid_new ();
    notebook = gtk_notebook_new ();
    gtk_notebook_set_tab_pos (GTK_NOTEBOOK (notebook), GTK_POS_TOP);
    gtk_grid_attach(GTK_GRID (grid), notebook, 0, 0, 1000, 500);
 
    // log viewer page
    label = gtk_label_new ("Log Viewer");
    gtk_notebook_insert_page(GTK_NOTEBOOK(notebook), vbox, label, 0);
 
    // log analyzer page
    label2 = gtk_label_new ("Log Analyzer");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), vbox_analyzer, label2);
 
    gtk_notebook_set_current_page (GTK_NOTEBOOK (notebook), 0);
    gtk_widget_set_size_request(notebook, 1000, 500);
 
    gtk_container_add(GTK_CONTAINER(window), grid);
}

void *calculate_median()
{
    time_t t;
    float now = 0;

    while(1) {
        sleep(5);
        now = (float)from_before_median_count / (float)5;
        median = (float)(before_median + now) / (float)2;   
        from_before_median_count = 0;
        if( 0.8 < fabs(average-median))
            is_ddos = 1;
        else
            is_ddos = 0;
    }
   
}

void tail()
{
    gchar *buf = (char*)malloc(sizeof(gchar)*TAILOUT_BUFLEN);
    char str[TAILOUT_BUFLEN];
    FILE * fp;
 
    if(buf == NULL){
        printf("error\n");
        exit(1);
    }
 
    fp = fopen(filename, "r");

    if (fp == NULL) {
        printf("Failed to run command\n");
        exit (1);
    }

    while (fgets(str, TAILOUT_BUFLEN, fp) != NULL) {
        //printf("%s", str);
        //buf += result;
    }
 
 
    sprintf(buf, "%s", str);
    setLogline(buf);

    g_free(buf);
    fclose(fp);
}

void inotify_read_events(int fd)
{
    int count = 0;
    int i = 0;
    char buffer [BUF_LEN];
    int length = 0;

    if ((length = read(fd, buffer, BUF_LEN)) < 0)
        return;

    while (i < length) {
        struct inotify_event *event = (struct inotify_event *) &buffer[i];
        if (event->mask & IN_MODIFY) {
//            printf("%s file is modified\n", event->name);
        }
        i += EVENT_SIZE + event->len;
        count ++;
    }

    tail();
 

    return;
}

void *inotify_events_loop(void *data)
{
    int *temp = data;
    int fd = *temp;
    if(data == NULL) {
        printf("inotify events loop error\n");
        exit(1);
    }
   
    while(1) {
        pthread_mutex_trylock(&mutex);
        fd = *(int *)data;
        inotify_read_events(fd);
    }
}

int
main (int argc, char *argv[])
{
    GtkTreeSelection *selection;
    GtkTreeSelection *selection_unique_visitors;
    GtkTreeSelection *selection_web_attacks;
    pthread_t median_thread;
    pthread_t inotify_thread;
    
    int median_thread_id;
    int inotify_thread_id;

    int fd = -1;
    int wd = -1;
   
    time(&startTime);
    pthread_mutex_init(&mutex, NULL);

    head = NULL;
    ddos = 0;
    sql_injection = 0;
    rfi_lfi = 0;
    webshell = 0;
     //xss = 0;
    log_count = 0;
    from_before_median_count = 0;
    before_median = 0;
    median = 0;
    is_ddos = 0;

    // do not enter filepath
    if (argc != 2) {
        fprintf(stderr, "Usage: %s filepath\n", argv[0]);
        return 1;
    }

    filename = argv[1];

    if ((fd = inotify_init()) == -1) {
        perror("inotify_init");
        return 1;
    }

    wd = inotify_add_watch(fd, argv[1],
            IN_MODIFY | IN_CREATE | IN_DELETE);
 
    median_thread_id = pthread_create(&median_thread, NULL, calculate_median, NULL);
    if(median_thread_id < 0) {
        perror("thread create error");
        return 1;
    }

    inotify_thread_id = pthread_create(&inotify_thread, NULL, inotify_events_loop, (void*)&fd);
    if(inotify_thread_id < 0) {
        perror("thread create error");
        return 1;
    }
 

    // gtk
    gtk_init(&argc, &argv);

    gui();
    init_list(list);
 
    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
    selection_unique_visitors = gtk_tree_view_get_selection(GTK_TREE_VIEW(list_unique_visitors));
    gtk_tree_selection_set_mode (selection_unique_visitors, GTK_SELECTION_NONE);
    selection_web_attacks = gtk_tree_view_get_selection(GTK_TREE_VIEW(list_web_attacks));
    gtk_tree_selection_set_mode (selection_web_attacks, GTK_SELECTION_NONE);

    // signal
    g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(notebook, "switch-page", G_CALLBACK(analyze), NULL);
    g_signal_connect(list, "row-activated", G_CALLBACK(block_ip), NULL);
 
    gtk_widget_show_all(window);
    gtk_main();
    
    inotify_rm_watch(fd, wd);
    pthread_mutex_destroy(&mutex);

    close(fd);

    return 0;
} 