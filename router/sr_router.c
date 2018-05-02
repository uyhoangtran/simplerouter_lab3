/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

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

#include "arp.h"

#define ETH_HDR_SIZE sizeof(sr_ethernet_hdr_t)
#define IP_HDR_SIZE sizeof(sr_ip_hdr_t)

static int _verify_packet( uint8_t *eth_packet, unsigned int len)
{ 
  sr_ip_hdr_t *ip_hdr;
  uint16_t hdr_sum;
  uint16_t sum;
  uint8_t  hdr_len;

  if ( len < (ETH_HDR_SIZE + IP_HDR_SIZE) )
  {
    Debug("IP packet is invalid: not large enough to hold IP header\n");
    return -1;
  }

  ip_hdr = (sr_ip_hdr_t *)(eth_packet + ETH_HDR_SIZE);
  hdr_len = (ip_hdr->ip_hl)*4;
  hdr_sum = ip_hdr->ip_sum;

  ip_hdr->ip_sum = 0;
  sum = cksum(ip_hdr,hdr_len);
  if ( sum != hdr_sum)
  {
    Debug("IP packet is invalid: wrong header checksum hdr_sum=%d; my_sum=%d\n",hdr_sum,sum);
    return -1;
  }

  Debug("Checksum sucess: hdr_sum=%d; my_sum=%d \n",hdr_sum,sum);
  return 0;
}

static uint32_t _destination_ip(uint8_t *ip_packet)
{
  sr_ip_hdr_t *ip_hdr;
  ip_hdr = (sr_ip_hdr_t *)ip_packet;
  return ntohs(ip_hdr->ip_dst);
}

void arp_request_handler(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + ETH_HDR_SIZE);
  struct sr_if *if_struct;
  struct sr_arpentry * arp_entry;

  if_struct = sr_get_interface(sr, interface);
    Debug("IP: %d who is?\n",arp_hdr->ar_tip);

  if ((arp_hdr->ar_tip) == if_struct->ip)
  {
    Debug("It's me\n");
    sr_arpcache_insert(&sr->cache,if_struct->addr,if_struct->ip);
  }

  arp_entry = sr_arpcache_lookup(&sr->cache,arp_hdr->ar_tip);

  if (arp_entry)
  {
    Debug("have entry \n");
    uint8_t* buffer;
    buffer = calloc((ETH_HDR_SIZE + ARP_HDR_SIZE),1);
    create_arp_reply_packet(sr, buffer, arp_entry, arp_src_ip(packet + ETH_HDR_SIZE),\
                            arp_src_addr(packet +ETH_HDR_SIZE), interface);
    sr_send_packet(sr, buffer, ETH_HDR_SIZE + ARP_HDR_SIZE, interface);
    free(arp_entry);  /* Because pointer returned from sr_arpcache_lookup is just a copy of the entry in cache */ 
    free(buffer);
  }
  else
  {
    struct sr_arpreq *sr_arpreq;
    sr_arpreq = sr_arpcache_queuereq(&sr->cache,arp_dest_ip(packet + ETH_HDR_SIZE),packet, len, interface);
    handle_arpreq(sr, sr_arpreq);
  }
}

void arp_reply_handler(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  struct sr_arpreq *sr_arpreq;
  struct sr_packet *sr_packet;
  uint32_t ip;
  uint8_t mac[ETHER_ADDR_LEN];
  ip = arp_src_ip(packet + ETH_HDR_SIZE);
  memcpy(mac,arp_src_addr(packet + ETH_HDR_SIZE),ETHER_ADDR_LEN);
  sr_arpreq = sr_arpcache_insert(&sr->cache,mac,ip);

  if (sr_arpreq)
  {
    sr_packet = sr_arpreq->packets;
    while (NULL != sr_packet)
    {
      sr_send_packet(sr,sr_packet->buf,sr_packet->len,sr_packet->iface);
      sr_packet = sr_packet->next;
    }
    sr_arpreq_destroy(&sr->cache, sr_arpreq);
  }
}
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);
    struct sr_if* if_walker = 0;
    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */
    /* if_walker = sr->if_list;
    while(NULL != if_walker)
    {
      sr_arpcache_insert(&sr->cache,if_walker->addr,if_walker->ip);
      Debug("IP: %d save to cache\n",if_walker->ip);
      if_walker = if_walker->next;
    }
    */
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  uint16_t ether_type;
  ether_type = ethertype(packet);

  switch (ether_type)
  {
    case ethertype_ip:
    {
      Debug("Received IP packet \n");
      _verify_packet(packet,len);
      _destination_ip(packet + ETH_HDR_SIZE);
      break;
    }
    case ethertype_arp:
    {
      Debug("Received ARP packet:\n");
      enum sr_arp_opcode opcode = arp_opcode(packet + ETH_HDR_SIZE);
      switch (opcode)
      {
        case arp_op_request:
        {
          Debug(" ARP request\n");
          arp_request_handler(sr,packet,len,interface);
          break;
        }
        case arp_op_reply:
        {
          Debug(" ARP reply\n");
          arp_reply_handler(sr,packet,len,interface);
          break;
        }
      }
      break;
    }
  }
}/* end sr_ForwardPacket */
