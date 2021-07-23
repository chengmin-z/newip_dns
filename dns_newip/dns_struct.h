#ifndef DNS_STRUCT
#define DNS_STRUCT

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#define DOMAIN_MAX_LEN 255

#define ANSWER_NAME 0xc00c
#define ANSWER_TTL 0x00000068

enum ANSWER_TYPE {
    ANSWER_TYPE_NULL = 0x0000,
    ANSWER_TYPE_A = 0x0001,
    ANSWER_TYPE_AAAA = 0x001c,
    ANSWER_TYPE_NIP = 0x0036,
};

enum ANSWER_CLASS {
    ANSWER_CLASS_NULL = 0x0000,
    ANSWER_CLASS_IN = 0x0001
};

enum ANSWER_RDLENGTH {
    ANSWER_RDLENGTH_NULL = 0x0000,
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

unsigned short convertTypeToRDLen(enum ANSWER_TYPE type);

char *convertTypeToDescription(enum ANSWER_TYPE type);

void editDnsMessageAnswerRRs(char *dnsBuffer, uint16_t data);

void editDnsMessageFlag(char *dnsBuffer, uint16_t data);

void editDnsMessageInShortMode(char *dnsBuffer, int pos, unsigned short data);

void editDnsMessageInLongMode(char *dnsBuffer, int pos, unsigned long data);

void resolveRecv(char *recvBuf, int recvNum, char *domain, unsigned short *qclass, unsigned short *qtype);

#endif