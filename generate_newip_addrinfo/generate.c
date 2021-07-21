#include <stdio.h>
#include <stdlib.h>

#include "include/nipaddr_output.h"

#define MAX_ADDR_UCHAR 50

int main() {
    struct nip_addr saddr;
    saddr.level_num = 0x04;
    __u8 u8[16] = { 0x00, 0x88, 0x88, 0x88, 0x88, 0xff, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x45 };
    for (size_t i = 0; i < NEWIP_LEVEL_MAX; i++) {
        saddr.laddrs[i].u.top_addr.bitlen = 0xff;
        memcpy(saddr.laddrs[i].u.top_addr.v.u.u8, u8, 16);
    }
    u_char *buf = malloc(sizeof(u_char)*MAX_ADDR_UCHAR);
    u_char *p = buf;
    p = build_nip_addr(NIP_FIELDTYPE_SADDR, &saddr, buf);
    for (size_t i = 0; i < MAX_ADDR_UCHAR; i++) {
        printf("%x ", buf[i]);
    }
    putchar('\n');
    return 0;
}


