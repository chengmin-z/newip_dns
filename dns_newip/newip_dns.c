#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>

#define DNS_DEFAULT_OUTERADDR "10.3.9.45"
#define DNS_LOCALADDR "127.0.0.1"
#define DNS_PORT 53

#define DOMAIN_MAX_LEN 255

#define ANSWER_NAME 0xc00c
#define ANSWER_TTL 0x00000068

#define DNS_DEFAULT_FILE "dns_data.txt"

enum ANSWER_TYPE {
    ANSWER_TYPE_NULL = 0x0000,
    ANSWER_TYPE_A = 0x0001,
    ANSWER_TYPE_AAAA = 0x001c,
    ANSWER_TYPE_NIP = 0x0020,
};

enum ANSWER_CLASS {
    ANSWER_CLASS_NULL = 0x0000,
    ANSWER_CLASS_IN = 0x0001
};

enum ANSWER_RDLENGTH {
    ANSWER_RDLENGTH_A = 0x0004,
    ANSWER_RDLENGTH_AAAA = 0x0010,
    ANSWER_RDLENGTH_NIP = 0x0032
};

typedef struct dns_header {
    unsigned short ID;
    unsigned short Flags;
    unsigned short Questions;
    unsigned short AnswerRRs;
    unsigned short AuthorityRRs;
    unsigned short AddtionalRRs;
} DNS_Header;

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

typedef struct id_transform_item {
    unsigned short oldID;
    bool done;
    struct sockaddr_in client;
    char domain[DOMAIN_MAX_LEN];
    struct id_transform_item *next;
} ID_Transform_Item;

typedef struct id_transform_table {
    int size;
    struct id_transform_item *head;
} ID_Transform_Table;


bool checkargv(int argc, char *argv[], char *dnsFilePath, char *outerDNS);

struct dns_table * initDNSTable();

struct id_transform_table *initIDTransTable();

struct dns_table *importDomainTable(char *dnsFilePath);

void configSockAddr(struct sockaddr_in *name, char *addr);


int main(int argc, char *argv[]) {
    printf("******************DNS: 程序开始运行******************\n");
    char *dnsFilePath = DNS_DEFAULT_FILE;
    char *outerDNS = DNS_DEFAULT_OUTERADDR;
    if (!checkargv(argc, argv, dnsFilePath, outerDNS)) {
        printf("******************DNS: 参数输入错误******************\n");
        return 1;
    }
    
    struct id_transform_table *idTransTable = initIDTransTable();
    struct dns_table *dnsTable = importDomainTable(dnsFilePath);
    int localSerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    int remoteSerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in remoteSerName, localSerName, clientName;
    configSockAddr(&remoteSerName, outerDNS);
    configSockAddr(&remoteSerName, DNS_LOCALADDR);
    return 0;
}

bool checkargv(int argc, char *argv[], char *dnsFilePath, char *outerDNS) {
    if (argc == 1) {
        printf("STATE: 使用默认服务器: %s\n", outerDNS);
        printf("STATE: 使用默认配置文件: %s\n", dnsFilePath);
        return true;
    } else if (argc == 3) {
        outerDNS = argv[1];
        dnsFilePath = argv[2];
        printf("STATE: 使用指定服务器: %s\n", outerDNS);
        printf("STATE: 使用指定配置文件: %s\n", dnsFilePath);
        return true;
    } else {
        return false;
    }
}

struct dns_table *initDNSTable() {
    struct dns_table *table = malloc(sizeof(struct dns_table));
    table->size = 0;
    table->head = NULL;
    return table;
}

struct id_transform_table *initIDTransTable() {
    struct id_transform_table *table = malloc(sizeof(struct id_transform_table));
    table->size = 0;
    table->head = NULL;
    return table;
}

struct dns_table *importDomainTable(char *dnsFilePath) {
    struct dns_table *dnsTable = initDNSTable();
    return dnsTable;
}


void configSockAddr(struct sockaddr_in *name, char *addr) {
    name->sin_family = AF_INET;
    name->sin_port = htons(DNS_PORT);
    name->sin_addr.s_addr = inet_addr(addr);
}