
#include <stdio.h>
#include <assert.h>
#include <stdlib.h> 
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define IP_HDR_SIZE sizeof(sr_ip_hdr_t)
#define ICMP_HDR_SIZE sizeof(sr_icmp_hdr_t)

extern void icmp_handler(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
extern void tcp_udp_handler(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

extern struct sr_rt* sr_get_longest_prefix(struct sr_rt* rt, uint32_t ip);
extern void forwarding_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);