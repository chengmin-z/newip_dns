#include "dns_transtable.h"

struct id_transform_item *deleteIDTransItem(unsigned short newID, struct id_transform_table *table) {
    struct id_transform_item *currentItem = table->head;
    struct id_transform_item *lastItem = NULL;
    struct id_transform_item *resItem = NULL;
    while (currentItem != NULL) {
        if (currentItem->newID == newID) {
            resItem = currentItem;
            if (table->size == 1) {
                table->head = NULL;
                table->end = NULL;
            } else {
                if (table->head == currentItem) {
                    table->head = currentItem->next;
                } else if (table->end == currentItem) {
                    table->end = lastItem;
                } else {
                    lastItem->next = currentItem->next;
                }
            }
            table->size -= 1;
            break;
        }
        lastItem = currentItem;
        currentItem = currentItem->next;
    }
    return resItem;
}

unsigned short insertIDTransTable(struct id_transform_table *table, unsigned short oldID, struct sockaddr_in addr, char *domain) {
    struct id_transform_item *item = malloc(sizeof(struct id_transform_item));
    item->client = addr;
    item->oldID = oldID;
    item->newID = table->newID;
    item->next = NULL;

    if (table->head == NULL || table->size == 0) {
        table->head = item;
        table->end = item;
    } else {
        table->end->next = item;
        table->end = item;
    }

    table->newID += 1;
    table->size += 1;

    return item->newID;
}

struct id_transform_table *initIDTransTable() {
    struct id_transform_table *table = malloc(sizeof(struct id_transform_table));
    table->size = 0;
    table->newID = 0x0000;
    table->end = NULL;
    table->head = NULL;
    return table;
}