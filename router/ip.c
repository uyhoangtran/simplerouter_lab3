#include "ip.h"
#include "arp.h"

#define ETH_HDR_SIZE sizeof(sr_ethernet_hdr_t)

struct sr_rt* sr_get_longest_prefix(struct sr_rt* rt, uint32_t ip)
{
    Debug("longest pre ip: %x",ip);
    struct sr_rt* rt_walker = rt;
    struct sr_rt* rt_match = NULL;
    while(NULL != rt_walker)
    {
        if ( (ip&(rt_walker->mask.s_addr)) == rt_walker->dest.s_addr )
        {
            rt_match = rt_walker;
        }
        rt_walker = rt_walker->next;
    }
    return rt_match;
}

void send_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint32_t next_hop_ip)
{
    uint8_t *full_packet = malloc(len + IP_HDR_SIZE);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)full_packet;
    struct sr_arpentry *entry;
    struct sr_arpreq *arpreq;
    struct sr_if* my_if;
    uint8_t *src_mac;
    uint8_t *dst_mac;

    memcpy(full_packet + ETH_HDR_SIZE, packet,len);

    my_if = sr_get_interface(sr,interface);
    src_mac = my_if->addr;
    memcpy(eth_hdr->ether_shost,src_mac,ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    entry = sr_arpcache_lookup(&sr->cache,next_hop_ip);
    if (entry)
    {
        dst_mac = entry->mac;
        memcpy(eth_hdr->ether_dhost,dst_mac, ETHER_ADDR_LEN);
        sr_send_packet(sr,full_packet,len + ETH_HDR_SIZE,interface);
        free(full_packet);
    }
    else
    {
        arpreq = sr_arpcache_queuereq(&sr->cache,next_hop_ip,full_packet,len + ETH_HDR_SIZE,interface);
        handle_arpreq(sr,arpreq);
    }

}

void make_icmp_packet(struct sr_instance* sr, uint8_t *buffer, unsigned int len, char* interface,uint8_t type, uint8_t code, uint8_t *data)
{
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)buffer;
    
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;

    switch (type)
    {
        case 0:
        {
            memcpy(buffer + ICMP_HDR_SIZE, data,len - ICMP_HDR_SIZE);
            break;
        }
        case 3:
        {
            sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)buffer;
            sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)data;
            icmp_t3_hdr->unused = 0;
            icmp_t3_hdr->next_mtu = 0;
            
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum((uint8_t *)ip_hdr, IP_HDR_SIZE);
            memcpy(icmp_t3_hdr->data, data, ICMP_DATA_SIZE);
            break;
        }
    }

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(buffer,len);
}

void icmp_handler(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + ETH_HDR_SIZE);
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + ETH_HDR_SIZE + IP_HDR_SIZE);
    uint8_t *rep_pkt;
    uint16_t sum;
    uint32_t tmp;

    sum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    if (sum != cksum((uint8_t *)icmp_hdr, len - ETH_HDR_SIZE - IP_HDR_SIZE))
    {
        Debug("Wrong ICMP checksum %x %x\n", sum, cksum((uint8_t *)icmp_hdr, len - ETH_HDR_SIZE - IP_HDR_SIZE));
        return;
    }

    if (icmp_hdr->icmp_type == 8)
    {
        Debug("ICMP request\n");
        rep_pkt = malloc(len - ETH_HDR_SIZE);
        
        memcpy(rep_pkt, packet + ETH_HDR_SIZE, IP_HDR_SIZE);
        ip_hdr = (sr_ip_hdr_t *)rep_pkt;
        tmp = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = tmp;

        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(rep_pkt, IP_HDR_SIZE);
        make_icmp_packet(sr,rep_pkt + IP_HDR_SIZE, len - ETH_HDR_SIZE - IP_HDR_SIZE, interface,0,0,packet + ETH_HDR_SIZE + IP_HDR_SIZE + ICMP_HDR_SIZE);
        send_ip_packet(sr,rep_pkt, len - ETH_HDR_SIZE,interface,ntohl(ip_hdr->ip_dst));
        free(rep_pkt);
    }
}

void forwarding_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + ETH_HDR_SIZE);
    struct sr_rt* rt_entry;
    uint8_t *send_pkt;

    ip_hdr->ip_ttl--;
    if (ip_hdr->ip_ttl == 0)
    {
        return;
    }

    rt_entry = sr_get_longest_prefix(sr->routing_table,(ip_hdr->ip_dst));
    if (NULL != rt_entry)
    {
        ip_hdr->ip_sum = cksum(ip_hdr, IP_HDR_SIZE);

        send_pkt = malloc(len - ETH_HDR_SIZE);
        memcpy(send_pkt,packet + ETH_HDR_SIZE, len - ETH_HDR_SIZE);
        send_ip_packet(sr,send_pkt, len - ETH_HDR_SIZE, rt_entry->interface, ntohl(rt_entry->gw.s_addr));
    }
    else
    {
        Debug("Destination unreachable\n");
        send_pkt = malloc(IP_HDR_SIZE + sizeof(sr_icmp_t3_hdr_t));
        memcpy(send_pkt,(uint8_t *)ip_hdr,IP_HDR_SIZE);
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)send_pkt;
        struct sr_if* my_if = sr_get_interface(sr,interface);

        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = my_if->ip;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_len = htons(IP_HDR_SIZE + sizeof(sr_icmp_t3_hdr_t));
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum((uint8_t *)ip_hdr, IP_HDR_SIZE);

        make_icmp_packet(sr,send_pkt + IP_HDR_SIZE, sizeof(sr_icmp_t3_hdr_t),interface,3, 0, packet + ETH_HDR_SIZE);
        send_ip_packet(sr,send_pkt, IP_HDR_SIZE + sizeof(sr_icmp_t3_hdr_t),interface,ntohl(ip_hdr->ip_dst));
    }

    free(send_pkt);
}