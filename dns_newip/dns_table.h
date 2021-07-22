#ifndef DNS_TABLE
#define DNS_TABLE

#include <stdio.h>
#include "dns_struct.h"

#define MAX_LINE 512

typedef struct dns_table_item {
    char domain[DOMAIN_MAX_LEN];
    enum ANSWER_TYPE type;
    unsigned char *rdata;
    struct dns_table_item *next;
} DNS_Table_Item;

typedef struct dns_table {
    int size;
    struct dns_table_item *head;
} DNS_Table;

struct dns_table *initDNSTable();

struct dns_table *importDomainTable(char *dnsFilePath);

struct dns_table_item *findDnsItem(char *domain, struct dns_table *dnsTable);

int addDNSMessageAnswer(char *dnsBuffer, int size, struct dns_table_item *dnsItem);

unsigned char __hexString2UnsignedChar(char *input);

#endif