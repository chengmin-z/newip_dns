#include "nipaddr_output.h"

u_char* build_nip_addr(u_char type, const struct nip_addr *addr, u_char *buf){
    u_char *p = buf;
    u_char *plen;
    int i;
    *p = type;
    p++;
    plen = p;
    p++;
    for(i = 0; i < addr->level_num; i++){
        int len = addr->laddrs[i].u.top_addr.bitlen >> 3;
        *p = len;
        p++;
        memcpy(p, &addr->laddrs[i].u.top_addr.v.u, len);
        p+= len;
    }

    *plen = p - plen - 1;
    return p;
}