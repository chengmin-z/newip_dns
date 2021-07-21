#include <stdio.h>
#include <stdlib.h>

#include "include/nipaddr_output.h"

#define MAX_ADDR_UCHAR 50

struct nip_addr saddr;

struct nip_addr *build_nipaddr_struct(uint8_t levelnum, uint8_t bitlen1, __u8 u8_1[], uint8_t bitlen2, __u8 u8_2[], uint8_t bitlen3, __u8 u8_3[], uint8_t bitlen4, __u8 u8_4[]);

int main() {
    uint8_t bitlen = 0x80;
    __u8 u8[16] = { 0x00, 0x88, 0x88, 0x88, 0x88, 0xff, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x45 };
    struct nip_addr *addr = build_nipaddr_struct(0x04, bitlen, u8, bitlen, u8, bitlen, u8, bitlen, u8);
    u_char *buf = malloc(sizeof(u_char)*MAX_ADDR_UCHAR);
    u_char *p = buf;
    p = build_nip_addr(NIP_FIELDTYPE_SADDR, addr, buf);
    for (size_t i = 0; i < MAX_ADDR_UCHAR; i++) {
        printf("%x ", buf[i]);
    }
    putchar('\n');
    return 0;
}


struct nip_addr *build_nipaddr_struct(uint8_t levelnum, uint8_t bitlen1, __u8 u8_1[], uint8_t bitlen2, __u8 u8_2[], uint8_t bitlen3, __u8 u8_3[], uint8_t bitlen4, __u8 u8_4[])
{
    saddr.level_num = levelnum;
    for (size_t i = 0; i < levelnum; i++) {
        if (i==0) {
            saddr.laddrs[i].u.top_addr.bitlen = bitlen1;
            memcpy(saddr.laddrs[i].u.top_addr.v.u.u8, u8_1, ((int)bitlen1)/8);
        }
        if (i==1) {
            saddr.laddrs[i].u.top_addr.bitlen = bitlen2;
            memcpy(saddr.laddrs[i].u.top_addr.v.u.u8, u8_2, ((int)bitlen2)/8);
        }
        if (i==2) {
            saddr.laddrs[i].u.top_addr.bitlen = bitlen3;
            memcpy(saddr.laddrs[i].u.top_addr.v.u.u8, u8_3, ((int)bitlen3)/8);
        }
        if (i==3) {
            saddr.laddrs[i].u.top_addr.bitlen = bitlen4;
            memcpy(saddr.laddrs[i].u.top_addr.v.u.u8, u8_4, ((int)bitlen4)/8);
        }
    }
    return &saddr;
}