#include <stdio.h>
#include <gtk/gtk.h>
#include "sleep.h"

void
analyze (GtkNotebook *notebook,
         GtkWidget   *page,
         guint        page_num,
         gpointer     user_data)
{
    struct byIP *temp = head;
    int count = 1;
 
    if(page_num == 0)
        return;

    gtk_list_store_clear(store2);
    gtk_list_store_clear(store_web_attacks);
    gtk_list_store_clear(store_total_logs);
 
    while(temp != NULL) {
        store2 = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list_unique_visitors)));
        gtk_list_store_append(store2, &iter2);
        gtk_list_store_set(store2, &iter2,
                   COL_RANKING, count,
                   COL_HOST, temp->ip,
                   COL_COUNT, temp->today,
                    COL_VALUE_PROGRESS_VISIBLE, TRUE,
                    COL_VALUE_PROGRESS_VALUE, (temp->today)/10,
                    COL_VALUE_PROGRESS_TEXT, " ",
                   -1);
        temp = temp->nextIP;
        count++;
        }
 
    store_web_attacks = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list_web_attacks)));

    gtk_list_store_append(store_web_attacks, &iter_web_attacks);
    gtk_list_store_set(store_web_attacks, &iter_web_attacks,
                   COL_ATTACK_NAME, "DDoS",
                   COL_ATTACK_COUNT, ddos,
                     COL_ATTACK_PROGRESS_VISIBLE, TRUE,
                   COL_ATTACK_PROGRESS_VALUE, (ddos)/10,
                   COL_ATTACK_PROGRESS_TEXT, " ",
                   -1);

    gtk_list_store_append(store_web_attacks, &iter_web_attacks);
    gtk_list_store_set(store_web_attacks, &iter_web_attacks,
                   COL_ATTACK_NAME, "SQL Injection",
                   COL_ATTACK_COUNT, sql_injection,
                    COL_ATTACK_PROGRESS_VISIBLE, TRUE,
                   COL_ATTACK_PROGRESS_VALUE, (sql_injection)/10,
                   COL_ATTACK_PROGRESS_TEXT, " ",
                   -1);

    gtk_list_store_append(store_web_attacks, &iter_web_attacks);
    gtk_list_store_set(store_web_attacks, &iter_web_attacks,
                   COL_ATTACK_NAME, "RFI LFI",
                   COL_ATTACK_COUNT, rfi_lfi,
                    COL_ATTACK_PROGRESS_VISIBLE, TRUE,
                   COL_ATTACK_PROGRESS_VALUE, (rfi_lfi)/10,
                   COL_ATTACK_PROGRESS_TEXT, " ",
                   -1);

    gtk_list_store_append(store_web_attacks, &iter_web_attacks);
    gtk_list_store_set(store_web_attacks, &iter_web_attacks,
                   COL_ATTACK_NAME, "Webshell",
                   COL_ATTACK_COUNT, webshell,
                    COL_ATTACK_PROGRESS_VISIBLE, TRUE,
                   COL_ATTACK_PROGRESS_VALUE, (webshell)/10,
                   COL_ATTACK_PROGRESS_TEXT, " ",
                   -1);


    store_total_logs = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(list_total_logs)));

    gtk_list_store_append(store_total_logs, &iter_total_logs);
    gtk_list_store_set(store_total_logs, &iter_total_logs,
                   COL_TOTAL_COUNT, sum_logs,
                   -1);

} 