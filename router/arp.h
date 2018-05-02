#ifndef ARP_H
#define ARP_H


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

#define ARP_HDR_SIZE sizeof(sr_arp_hdr_t)


extern unsigned short arp_opcode(uint8_t *arp_packet);
extern uint32_t arp_dest_ip(uint8_t *arp_packet);
extern unsigned char *arp_dest_addr(uint8_t *arp_packet);

extern uint32_t arp_src_ip(uint8_t *arp_packet);
extern unsigned char *arp_src_addr(uint8_t *arp_packet);

extern void create_arp_reply_packet(struct sr_instance* sr, uint8_t *buffer, 
                            struct sr_arpentry *arp_entry, uint32_t dest_ip,
                            unsigned char* dest_addr, char* interface);

extern void create_arp_request_packet(struct sr_instance* sr, uint8_t *buffer, 
                            struct sr_arpreq *sr_arpreq,char* interface);

extern void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *sr_arpreq);

#endif