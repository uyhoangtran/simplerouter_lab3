#include "arp.h"
#define ETH_HDR_SIZE sizeof(sr_ethernet_hdr_t)

unsigned char bc_addr[ETHER_ADDR_LEN]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

unsigned short arp_opcode(uint8_t *arp_packet)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)arp_packet;
  return ntohs(arp_hdr->ar_op);
}

uint32_t arp_dest_ip(uint8_t *arp_packet)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)arp_packet;
  return ntohl(arp_hdr->ar_tip);
}

unsigned char *arp_dest_addr(uint8_t *arp_packet)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)arp_packet;
  return arp_hdr->ar_tha;
}

uint32_t arp_src_ip(uint8_t *arp_packet)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)arp_packet;
  return ntohl(arp_hdr->ar_sip);
}

unsigned char *arp_src_addr(uint8_t *arp_packet)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)arp_packet;
  return arp_hdr->ar_sha;
}

void create_arp_reply_packet(struct sr_instance* sr, uint8_t *buffer, 
                            struct sr_arpentry *arp_entry, uint32_t dest_ip,
                            unsigned char* dest_addr, char* interface)
{
    sr_ethernet_hdr_t *eth_hdr;
    sr_arp_hdr_t *arp_hdr;
    struct sr_if* if_struct;

    eth_hdr = (sr_ethernet_hdr_t *)buffer;
    if_struct = sr_get_interface(sr,interface);
    memcpy(eth_hdr->ether_shost, if_struct->addr, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, dest_addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    arp_hdr = (sr_arp_hdr_t *)(buffer + ETH_HDR_SIZE);
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(arp_hdr->ar_sha, arp_entry->mac, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = arp_entry->ip;     /* IP in ARP_ENTRY is already in network byte order */
    memcpy(arp_hdr->ar_tha, dest_addr, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = htonl(dest_ip);
}

extern void create_arp_request_packet(struct sr_instance* sr, uint8_t *buffer, 
                            struct sr_arpreq *sr_arpreq,char* interface)
{
    sr_ethernet_hdr_t *eth_hdr;
    sr_arp_hdr_t *arp_hdr;
    struct sr_if* if_struct;

    eth_hdr = (sr_ethernet_hdr_t *)buffer;
    if_struct = sr_get_interface(sr,interface);
    memcpy(eth_hdr->ether_shost, if_struct->addr, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, bc_addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    arp_hdr = (sr_arp_hdr_t *)(buffer + ETH_HDR_SIZE);
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, if_struct->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = (if_struct->ip);
    memcpy(arp_hdr->ar_tha, bc_addr, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = htonl(sr_arpreq->ip);
}

/* function handle_arpreq(req):
       if difftime(now, req->sent) >= 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++
*/

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *sr_arpreq)
{
    time_t now;
    uint8_t *buffer;
    struct sr_if* if_walker = 0;

    now = time(NULL);
    if (difftime(now, sr_arpreq->sent) >= 1.0)
    {
        if (sr_arpreq->times_sent >= 5)
        {
            sr_arpreq_destroy(&sr->cache, sr_arpreq);
        }
        else
        {
            buffer = calloc(ETH_HDR_SIZE + ARP_HDR_SIZE, 1);
            if_walker = sr->if_list;

            while(NULL != if_walker)
            {
                memset(buffer, 0, ETH_HDR_SIZE + ARP_HDR_SIZE);
                create_arp_request_packet(sr, buffer,sr_arpreq,if_walker->name);
                sr_send_packet(sr, buffer, ETH_HDR_SIZE + ARP_HDR_SIZE, if_walker->name);

                if_walker = if_walker->next;
            }
            free(buffer);
            sr_arpreq->sent = now;
            sr_arpreq->times_sent++;
        }
    }
}