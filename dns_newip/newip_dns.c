#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define DNS_DEFAULT_OUTERADDR "10.3.9.45"
#define DNS_LOCALADDR "127.0.0.1"
#define DNS_PORT 53

#define DOMAIN_MAX_LEN 255

#define ANSWER_NAME 0xc00c
#define ANSWER_TTL 0x00000068

#define DNS_DEFAULT_FILE "dns_data.txt"

#define BUFFER_MAX_SIZE 512

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


bool checkargv(int argc, char *argv[], char *dnsFilePath, char *outerDNS);

struct dns_table * initDNSTable();

struct id_transform_table *initIDTransTable();

struct dns_table *importDomainTable(char *dnsFilePath);

void configSockAddr(struct sockaddr_in *name, char *addr);

int checkfdSet(int localSerSocket, int remoteSerSocket, fd_set *fdSet, struct timeval *timeout);

void resolveRecv(char *recvBuf, int recvNum, char *domain, unsigned short *qclass, unsigned short *qtype);

struct dns_table_item *findDnsItem(char *domain, struct dns_table *dnsTable);

unsigned short insertIDTransTable(struct id_transform_table *table, unsigned short oldID, struct sockaddr_in addr, char *domain);

unsigned short convertTypeToRDLen(enum ANSWER_TYPE type);

int addDNSMessageAnswer(char *dnsBuffer, int size, struct dns_table_item *dnsItem);

void editDnsMessageAnswerRRs(char *dnsBuffer, uint16_t data);

void editDnsMessageFlag(char *dnsBuffer, uint16_t data);

void editDnsMessageInShortMode(char *dnsBuffer, int pos, unsigned short data);

void editDnsMessageInLongMode(char *dnsBuffer, int pos, unsigned long data);

struct id_transform_item *deleteIDTransItem(unsigned short newID, struct id_transform_table *table);


int main(int argc, char *argv[]) {

    printf("******************DNS: Progrm Start******************\n");
    char *dnsFilePath = DNS_DEFAULT_FILE;
    char *outerDNS = DNS_DEFAULT_OUTERADDR;
    if (!checkargv(argc, argv, dnsFilePath, outerDNS)) {
        printf("****************DNS: Arg Format Error****************\n");
        return 1;
    }
    
    struct id_transform_table *idTransTable = initIDTransTable();
    struct dns_table *dnsTable = importDomainTable(dnsFilePath);
    int localSerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    int remoteSerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in remoteSerName, localSerName, clientName;
    socklen_t addrLength = sizeof(clientName);
    char currentDomain[DOMAIN_MAX_LEN];
    unsigned short qclass, qtype;

    configSockAddr(&remoteSerName, outerDNS);
    configSockAddr(&localSerName, DNS_LOCALADDR);
    if (bind(localSerSocket, (struct sockaddr *) &localSerName, sizeof(localSerName)) == -1) {
        printf("ERROR: Binding Local Port 53 failed.\n");
        printf("WARNS: Binding Failed: %s(errno: %d)\n", strerror(errno), errno);
        printf("******************DNS: Program Exit******************\n");
        return 1;
    } else {
        printf("STATE: Binding Local Port 53 succeed\n");
    }

    struct timeval timeout;
    fd_set fdSet;
    char sendBuf[BUFFER_MAX_SIZE];
    char recvBuf[BUFFER_MAX_SIZE];


    while (true) {
        int ret = checkfdSet(localSerSocket, remoteSerSocket, &fdSet, &timeout);

        if (ret < 0) {
            printf("ERROR: Select Error!\n");
            break;
        } else if (ret == 0) {
            printf("ERROR: Timeout\n");
            continue;
        }

        memset(recvBuf, 0, BUFFER_MAX_SIZE);
        memset(sendBuf, 0, BUFFER_MAX_SIZE);

        if (FD_ISSET(localSerSocket, &fdSet)) {
            int recvNum = recvfrom(localSerSocket, recvBuf, sizeof(recvBuf), 0, (struct sockaddr *) &clientName, &addrLength);
            if (recvNum == -1) {
                printf("WARNS: RecvFrom Failed: %s(errno: %d)\n", strerror(errno), errno);
            } else if (recvNum == 0) {
            } else {
                resolveRecv(recvBuf, recvNum, currentDomain, &qclass, &qtype);
                struct dns_table_item *findItem = findDnsItem(currentDomain, dnsTable);
                if (findItem == NULL) {
                    // not in dns table
                    unsigned short oldID;
                    memcpy(&oldID, recvBuf, sizeof(unsigned short));
                    unsigned short newID = htons(insertIDTransTable(idTransTable, ntohs(oldID), clientName, currentDomain));
                    memcpy(recvBuf, &newID, sizeof(unsigned short));

                    int send = sendto(remoteSerSocket, recvBuf, recvNum, 0,
                                       (struct sockaddr *) &remoteSerName, sizeof(remoteSerName));

                    if (send == -1) {
                        printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                    }
                } else {
                    // in dns table
                    memcpy(sendBuf, recvBuf, recvNum);
                    int sendNum = recvNum;
                    if (findItem->type == ANSWER_TYPE_NULL) {
                        editDnsMessageFlag(sendBuf, 0x8183);
                    } else {
                        editDnsMessageFlag(sendBuf, 0x8180);
                        editDnsMessageAnswerRRs(sendBuf, 0x0001);
                        sendNum = addDNSMessageAnswer(sendBuf, sendNum, findItem);
                    }
                    int send = sendto(localSerSocket, sendBuf, sendNum, 0,
                                       (struct sockaddr *) &clientName, sizeof(clientName));

                    if (send == -1) {
                        printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                    }
                }
            }
        }

        if (FD_ISSET(remoteSerSocket, &fdSet)) {
            int recvNum = recvfrom(remoteSerSocket, recvBuf, sizeof(recvBuf), 0,
                                  (struct sockaddr *) &remoteSerSocket, &addrLength);
            if (recvNum == -1) {
                printf("WARNS: RecvFrom Failed: %s(errno: %d)\n", strerror(errno), errno);
            } else if (recvNum == 0) {
            } else {
                unsigned short recvID;
                memcpy(&recvID, recvBuf, sizeof(unsigned short));
                unsigned short newID = htons(recvID);
                struct id_transform_item *item = deleteIDTransItem(newID, idTransTable);
                memcpy(recvBuf, &(item->oldID), 2);
                clientName = item->client;
                int send = sendto(localSerSocket, recvBuf, recvNum, 0,
                           (struct sockaddr *) &clientName, sizeof(clientName));
                if (send == -1) {
                    printf("WARNS: Sendto Failed: %s(errno: %d)\n", strerror(errno), errno);
                }
                free(item);
            }
        }
    }

    printf("******************DNS: Program Exit******************\n");
    return 0;
}


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

int addDNSMessageAnswer(char *dnsBuffer, int size, struct dns_table_item *dnsItem) {
    // ANSWER NAME
    editDnsMessageInShortMode(dnsBuffer, size, 0xc00c);
    size += 2;
    // TYPE
    editDnsMessageInShortMode(dnsBuffer, size, dnsItem->type);
    size += 2;
    // CLASS
    editDnsMessageInShortMode(dnsBuffer, size, 0x0001);
    size += 2;
    // TTL
    editDnsMessageInLongMode(dnsBuffer, size, 0x000000ce);
    size += 4;
    // RDLENGTH
    unsigned short len = convertTypeToRDLen(dnsItem->type);
    editDnsMessageInShortMode(dnsBuffer, size, len);
    size += 2;
    // RDATA
    memcpy(&dnsBuffer[size], dnsItem->rdata, len);
    size += len;
    return size;
}

void editDnsMessageAnswerRRs(char *dnsBuffer, uint16_t data) {
    editDnsMessageInShortMode(dnsBuffer, 6, data);
}

void editDnsMessageFlag(char *dnsBuffer, uint16_t data) {
    editDnsMessageInShortMode(dnsBuffer, 2, data);
}

void editDnsMessageInShortMode(char *dnsBuffer, int pos, unsigned short data) {
    unsigned short shiftdata = htons(data);
    memcpy(&dnsBuffer[pos], &shiftdata, 2);
}

void editDnsMessageInLongMode(char *dnsBuffer, int pos, unsigned long data) {
    unsigned long shiftdata = htonl(data);
    memcpy(&dnsBuffer[pos], &shiftdata, 4);
}


unsigned short convertTypeToRDLen(enum ANSWER_TYPE type) {
    unsigned short len = ANSWER_RDLENGTH_A;
    switch (type) {
        case ANSWER_TYPE_A:
            len = ANSWER_RDLENGTH_A;
            break;
        case ANSWER_TYPE_AAAA:
            len = ANSWER_RDLENGTH_AAAA;
            break;
        case ANSWER_TYPE_NIP:
            len = ANSWER_RDLENGTH_NIP;
            break;
        default:
            break;
    }
    return len;
}

struct dns_table_item *findDnsItem(char *domain, struct dns_table *dnsTable) {
    struct dns_table_item *currentItem = dnsTable->head;
    struct dns_table_item *resItem = NULL;
    while (currentItem != NULL) {
        if (strcmp(currentItem->domain, domain) == 0) {
            resItem = currentItem;
            break;
        }
        currentItem = currentItem->next;
    }
    return resItem;
}


void resolveRecv(char *recvBuf, int recvNum, char *domain, unsigned short *qclass, unsigned short *qtype) {
    char urlName[DOMAIN_MAX_LEN];
    int i = 0, j, k = 0;

    memset(domain, 0, DOMAIN_MAX_LEN);
    memset(qclass, 0, sizeof(*qclass));
    memset(qtype, 0, sizeof(*qtype));
    unsigned short tmp;
    memcpy(&tmp, &(recvBuf[recvNum - 4]), 2);
    *qtype = ntohs(tmp);
    memcpy(&tmp, &(recvBuf[recvNum - 2]), 2);
    *qclass = ntohs(tmp);
    memcpy(urlName, &(recvBuf[sizeof(struct dns_header)]), recvNum - 16);
    int len = strlen(urlName);

    while (i < len) {
        if (urlName[i] > 0 && urlName[i] <= 63)
            for (j = urlName[i], i++; j > 0; j--, i++, k++)
                domain[k] = urlName[i];

        if (urlName[i] != 0) {
            domain[k] = '.';
            k++;
        }
    }
    domain[k] = '\0';
}


int checkfdSet(int localSerSocket, int remoteSerSocket, fd_set *fdSet, struct timeval *timeout) {
    timeout->tv_sec = 5000;
    timeout->tv_usec = 0;
    FD_ZERO(fdSet);
    FD_SET(remoteSerSocket, fdSet);
    FD_SET(localSerSocket, fdSet);
    int maxFds =
                remoteSerSocket > localSerSocket ? remoteSerSocket + 1 : localSerSocket + 1;
    int ret = select(maxFds, fdSet, NULL, NULL, timeout);
    return ret;
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
    table->newID = 0x0000;
    table->end = NULL;
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

bool checkargv(int argc, char *argv[], char *dnsFilePath, char *outerDNS) {
    if (argc == 1) {
        printf("STATE: Use Default Remote Server: %s\n", outerDNS);
        printf("STATE: Use Default DNS File: %s\n", dnsFilePath);
        return true;
    } else if (argc == 3) {
        outerDNS = argv[1];
        dnsFilePath = argv[2];
        printf("STATE: Use Custom Remote Server: %s\n", outerDNS);
        printf("STATE: Use Custom DNS File: %s\n", dnsFilePath);
        return true;
    } else {
        return false;
    }
}