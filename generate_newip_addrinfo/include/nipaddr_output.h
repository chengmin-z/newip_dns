/*
 *	Types and definitions for AF_NINET and NIN_ADDR OUTPUT
 *	Linux NEWIP DNS Table implementation 
 *
 */

#ifndef NIPADDR_OUTPUT
#define NIPADDR_OUTPUT


#include "nin.h"

typedef unsigned char u_char;

#define NIP_FIELDTYPE_SADDR 1
#define NIP_FIELDTYPE_DADDR 2

u_char* build_nip_addr(u_char type, const struct nip_addr *addr, u_char *buf);


#endif /* NIPADDR_OUTPUT_H */