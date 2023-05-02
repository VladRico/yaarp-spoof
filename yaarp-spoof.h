//
// Created by vlad on 4/30/23.
//


#ifndef C_ARP_SPOOF_H
#define C_ARP_SPOOF_H

#include <net/if_arp.h>
#include <net/ethernet.h>
#include <pcap.h>

typedef struct{
    unsigned char target_ip[4];
    unsigned char impersonate_ip[4];
    unsigned char target_mac[ETH_ALEN];
    unsigned char impersonate_mac[ETH_ALEN];
    unsigned char random_mac[ETH_ALEN];
    unsigned char original_mac[ETH_ALEN];
    char *interface;
} __attribute__((packed)) AttackSettings;

typedef struct {
    unsigned char ar_sha[ETH_ALEN]; /* Sender hardware address.  */
    unsigned char ar_sip[4]; /* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN]; /* Target hardware address.  */
    unsigned char ar_tip[4]; /* Target IP address.  */
}__attribute__((packed)) ArpBody;


typedef struct {
    struct arphdr header;
    ArpBody body;
} __attribute__((packed)) ArpPacket;

typedef struct {
    struct ether_header eth_header;
    ArpPacket arp;
} __attribute__((packed)) Packet;

typedef struct {
    char *interface;
    Packet p[2];
    char *filter;
} threadArgs;


void generateRandomMacAddr(unsigned char* mac_addr);
int changeMacAddr(unsigned char* mac_addr, char* interface);
int getMacAddr(unsigned char original_mac[ETH_ALEN], const char* interface);
int resolveMacAddr(char *interface, unsigned char *target_ip, unsigned char *random_mac, unsigned char *resolved_mac);
char* getIpFromInterface(char* name);
Packet*
craftPacket(unsigned char *sender_mac, unsigned char* sender_ip, unsigned char *target_mac, unsigned char *target_ip, int ARPOP_CODE);
pcap_t*
prepareConnection(char* interface);
int sendArpPacket(pcap_t *handle, Packet *packet);
int
receiveArpPacket(pcap_t *handle, uint8_t mac[ETH_ALEN]);
void* threadSendArpPacket(void* tArgs);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const
u_char *pkt_data);
void* threadHandlePacket(void* tArgs);

#endif //C_ARP_SPOOF_H
