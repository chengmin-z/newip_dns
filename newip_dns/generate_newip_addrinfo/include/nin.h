/*
 *	Types and definitions for AF_NINET
 *	Linux NEWIP implementation 
 *
 */

#ifndef _UAPI_LINUX_NIN_H
#define _UAPI_LINUX_NIN_H

#include <linux/types.h>
#include <linux/libc-compat.h>
#include <stdint.h>

#define NIP_8BIT_MAX 0xEF

#define NIP_ADDR_8BIT 0xF0
#define NIP_ADDR_16BIT 0xF1
#define NIP_ADDR_32BIT 0xF2
#define NIP_ADDR_64BIT 0xF3
#define NIP_ADDR_128BIT 0xF4

#define NIP_LEV_2 0xF6
#define NIP_LEV_3 0xF7
#define NIP_LEV_4 0xF8

#define NIP_BITTER_MAX 128
/*
 * newIP address field
 */
struct nip_addr_field {
	union {
		__u8        u8[16];
		__be16      u16[8];
		__be32      u32[4];
	} u;
};

/*
 * newIP topology address
 */
struct nip_top_addr{
	uint8_t bitlen; // address bitlength
	uint8_t resv;
	uint16_t resv2;
	struct nip_addr_field v;
};

/*
 * level address include topology address and non topology address, such as service ID
 */
#define LEVEL_ADDR_TYPE_TOP
#define LEVEL_ADDR_TYPE_NON_TOP
struct nip_level_addr{
	uint8_t type;
	uint8_t recv;
	uint16_t recv2;
	union {
		struct nip_top_addr top_addr;
		struct nip_addr_field field;
	}u;
};

#define nip_addr_bitlen u.top_addr.bitlen
#define nip_addr_field8 u.top_addr.v.u.u8
#define nip_addr_field16 u.top_addr.v.u.u16
#define nip_addr_field32 u.top_addr.v.u.u32


#define NEWIP_LEVEL_MAX 4
/*
 * newIP address structure
 */
struct nip_addr {
	uint8_t level_num; // address level num  
	struct nip_level_addr  laddrs[NEWIP_LEVEL_MAX];
};
typedef struct nip_addr nip_addr_t;

/*
 *newIP network address structure
 *The currently defined name is in dispute
 */
struct sockaddr_nin{
	unsigned short int sin_family; /*AF_NINET*/
	__be16 sin_port;                /*Transport layer port#*/
	// uint16_t sin_port;
	struct nip_addr sin_addr;      /*NIP address*/
};

/*
 * general LV data structure
 */
typedef struct nip_lvgen {
	uint8_t bitlen;
	uint8_t resv;
	uint16_t resv2;
} nip_lvgen_t;

typedef struct nip_lv16 {
	uint8_t bitlen;
	uint8_t resv;
	union {
		__u8        u8[2];
		__be16      u16[1];
	} v;
} nip_lv16_t;

typedef struct nip_lv32 {
	uint8_t bitlen;
	uint8_t resv;
	uint16_t resv2;
	union {
		__u8        u8[4];
		__be16      u16[2];
		__be32      u32[1];
	} v;
} nip_lv32_t;

typedef struct nip_lv64 {
	uint8_t bitlen;
	uint8_t resv;
	uint16_t resv2;
	union {
		__u8        u8[8];
		__be16      u16[4];
		__be32      u32[2];
	}v;
} nip_lv64_t;

typedef struct nip_lv128 {
	uint8_t bitlen;
	uint8_t resv;
	uint16_t resv2;
	union {
		__u8        u8[16];
		__be16      u16[8];
		__be32      u32[4]; 
	} v;
} nip_lv128_t;


#endif /* _UAPI_LINUX_NIN_H */
