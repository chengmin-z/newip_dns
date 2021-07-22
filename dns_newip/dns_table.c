#include "dns_table.h"

int addDNSMessageAnswer(char *dnsBuffer, int size, struct dns_table_item *dnsItem) {
    // ANSWER NAME
    editDnsMessageInShortMode(dnsBuffer, size, ANSWER_NAME);
    size += 2;
    // TYPE
    editDnsMessageInShortMode(dnsBuffer, size, dnsItem->type);
    size += 2;
    // CLASS
    editDnsMessageInShortMode(dnsBuffer, size, ANSWER_CLASS_IN);
    size += 2;
    // TTL
    editDnsMessageInLongMode(dnsBuffer, size, ANSWER_TTL);
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

struct dns_table *initDNSTable() {
    struct dns_table *table = malloc(sizeof(struct dns_table));
    table->size = 0;
    table->head = NULL;
    return table;
}

struct dns_table *importDomainTable(char *dnsFilePath) {
    struct dns_table *dnsTable = initDNSTable();

    FILE *tableFile = fopen(dnsFilePath, "rt");
    if (tableFile == NULL) {
        printf("STATE: Can Not Open %s File\n", dnsFilePath);
        printf("STATE: Import DNS Domain Info: %d\n", dnsTable->size);
        return dnsTable;
    }

    printf("STATE: Read %s File\n", dnsFilePath);
    char lineBuffer[MAX_LINE];
    while (fgets(lineBuffer, MAX_LINE, tableFile) != NULL) {
        int len = strlen(lineBuffer);
        if(lineBuffer[len - 1] == '\n') {
            lineBuffer[len - 1] = '\0';
            len -= 1;
        }
        char domain[DOMAIN_MAX_LEN], typeString[6], byteString[3];
        unsigned char *rdata = NULL;
        enum ANSWER_TYPE type = ANSWER_TYPE_NULL;
        int step = 1, dataIndex = 0, rlen = 0;
        size_t lastEnd = 0;
        for (size_t i = 0; i < len; i++) {
            if (lineBuffer[i] == ' ' || i == len - 1) {
                if (step == 1) {
                    strncpy(domain, lineBuffer, i);
                    domain[i] = '\0';
                    lastEnd = i + 1;
                    step += 1;
                    continue;
                }
                if (step == 2) {
                    for (size_t j = lastEnd; j < i; j++)
                        typeString[j - lastEnd] = lineBuffer[j];
                    typeString[i - lastEnd] = '\0';
                    if (strcmp(typeString, "A") == 0) {
                        type = ANSWER_TYPE_A;
                        rlen = 4;
                    } else if ((strcmp(typeString, "AAAA") == 0)) {
                        type = ANSWER_TYPE_AAAA;
                        rlen = 16;
                        rdata = malloc(sizeof(unsigned char) * 16);
                    } else if ((strcmp(typeString, "NIP") == 0)) {
                        type = ANSWER_TYPE_NIP;
                        rlen = 50;
                    } else {
                        type = ANSWER_TYPE_NULL;
                    }
                    rdata = malloc(sizeof(unsigned char) * rlen);
                    lastEnd = i + 1;
                    step += 1;
                    continue;
                }
                if (step == 3) {
                    for (size_t j = lastEnd; j < i; j++)
                        byteString[j - lastEnd] = lineBuffer[j];
                    byteString[3] = '\0';
                    unsigned char res = __hexString2UnsignedChar(byteString);
                    rdata[dataIndex] = res;
                    dataIndex += 1;
                    lastEnd = i + 1;
                    if (dataIndex >= rlen)
                        break;
                }
            }
        }
        printf("Domain: %s----\n", domain);
        printf("Type: %s\n", typeString);

        printf("Data:");
        for (size_t i = 0; i < rlen; i++) {
            printf(" %x", rdata[i]);
        }
        printf("\n");
        
        
    }
    
    
    return dnsTable;
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

unsigned char __hexString2UnsignedChar(char *input) {
    unsigned int res = 0;
    sscanf(input, "%x", &res);
    return (unsigned char)res;
}