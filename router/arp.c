#include "arp.h"
#include "ip.h"

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
    struct sr_rt* rt;
    struct sr_packet* packet;
    sr_ip_hdr_t *ip_hdr;
    now = time(NULL);
    if (difftime(now, sr_arpreq->sent) >= 1.0)
    {
        if (sr_arpreq->times_sent >= 5)
        {
            buffer = malloc(IP_HDR_SIZE + sizeof(sr_icmp_t3_hdr_t));
            packet = sr_arpreq->packets;
            while (NULL != packet)
            {
                ip_hdr = (sr_ip_hdr_t *)(packet->buf + ETH_HDR_SIZE);
                rt = sr_get_longest_prefix(sr->routing_table,ip_hdr->ip_src);
                if (NULL != rt)
                {
                    make_ip_hdr(sr,buffer,IP_HDR_SIZE + sizeof(sr_icmp_t3_hdr_t),rt->interface,ntohl(ip_hdr->ip_src),ip_protocol_icmp);
                    make_icmp_packet(sr,buffer + IP_HDR_SIZE, sizeof(sr_icmp_t3_hdr_t),rt->interface,3, 1, packet->buf + ETH_HDR_SIZE);
                    send_ip_packet(sr,buffer, IP_HDR_SIZE + sizeof(sr_icmp_t3_hdr_t),rt->interface,ntohl(ip_hdr->ip_src));
                }
                packet = packet->next;
            }

            free(buffer);
            sr_arpreq_destroy(&sr->cache, sr_arpreq);
        }
        else
        {
            rt = sr_get_longest_prefix(sr->routing_table,htonl(sr_arpreq->ip));
            if (NULL != rt)
            {
                buffer = calloc(ETH_HDR_SIZE + ARP_HDR_SIZE, 1);
                memset(buffer, 0, ETH_HDR_SIZE + ARP_HDR_SIZE);
                create_arp_request_packet(sr, buffer,sr_arpreq,rt->interface);
                sr_send_packet(sr, buffer, ETH_HDR_SIZE + ARP_HDR_SIZE, rt->interface);

                free(buffer);
                sr_arpreq->sent = now;
                sr_arpreq->times_sent++;
            }
        }
    }
}