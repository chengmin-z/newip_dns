#ifndef DNS_TRANSTABLE
#define DNS_TRANSTABLE

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct id_transform_item {
    unsigned short oldID;
    unsigned short newID;
    struct sockaddr_in client;
    struct id_transform_item *next;
} ID_Transform_Item;

typedef struct id_transform_table {
    unsigned short newID;
    int size;
    struct id_transform_item *head;
    struct id_transform_item *end;
} ID_Transform_Table;

struct id_transform_table *initIDTransTable();

unsigned short insertIDTransTable(struct id_transform_table *table, unsigned short oldID, struct sockaddr_in addr, char *domain);

struct id_transform_item *deleteIDTransItem(unsigned short newID, struct id_transform_table *table);

#endif