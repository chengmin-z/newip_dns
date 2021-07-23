#include "dns_struct.h"

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

unsigned short convertTypeToRDLen(enum ANSWER_TYPE type) {
    unsigned short len = ANSWER_RDLENGTH_NULL;
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

char *convertTypeToDescription(enum ANSWER_TYPE type) {
    switch (type) {
        case ANSWER_TYPE_A:
            return "A";
        case ANSWER_TYPE_AAAA:
            return "AAAA";
        case ANSWER_TYPE_NIP:
            return "NIP";
        default:
            return "NULL";
    }
}