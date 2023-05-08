//
// Created by @RicoVlad on 4/30/23.
//

#include <net/if_arp.h>
#include <net/ethernet.h>
#include <pcap.h>

#ifndef C_ARP_SPOOF_H
#define C_ARP_SPOOF_H


typedef struct{
    unsigned char target_ip[4];
    unsigned char impersonate_ip[4];
    unsigned char target_mac[ETH_ALEN];
    unsigned char impersonate_mac[ETH_ALEN];
    unsigned char random_mac[ETH_ALEN];
    unsigned char original_mac[ETH_ALEN];
    char *interface;
    char *argIP[2];
    char *filter;
    char *output;
    int retry;
    long int time;
} __attribute__((aligned)) AttackSettings;


/*
 * Have to define it here because only the fixed length is
 * defined in arphdr (net/if_arp.h)
 */
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
    pcap_t *handle_send;
    pcap_t *handle_receive;
    Packet *p[2];
    char *filter;
    char *output;
    long int time;
    int running;
} threadArgs;

const char *argp_program_version = "yaarp-spoof 0.3";
const char *argp_program_bug_address = "https://github.com/VladRico/yaarp-spoof/issues";
static const char doc[] = "ARP cache poisoning attack implemented in C for fun (and profit ?), using libpcap";
static const char args_doc[] = "-i <interface> <target_ip1> <target_ip2>";
static const struct argp_option options[] = {
        { "interface", 'i', "INTERFACE", 0, "Network interface to use"},
        { "retry", 'r', "NUMBER", 0, "Number of requests sent when trying to resolve targets mac addr (Default = 5)"},
        { "filter", 'f', "INFILE", 0, "Path to file containing a custom tcpdump filter"},
        { "output", 'o', "OUTFILE", 0, "Save the capture to a file (affected by filter option)"},
        { "time", 't', "DURATION", 0, "Time (in ns) between each spoofed ARP requests (Default = 50000)"},
        { 0 }
};
static error_t parse_opt(int key, char *arg, struct argp_state *state);
static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

void sigint_handler(int sig);
void generateRandomMacAddr(unsigned char* mac_addr);
int changeMacAddr(unsigned char* mac_addr, char* interface);
int getMacAddr(unsigned char original_mac[ETH_ALEN], const char* interface);
int resolveMacAddr(char *interface, unsigned char *target_ip, unsigned char *random_mac, unsigned char *resolved_mac, int nbRetries);
char* getIpFromInterface(char* name);
Packet* craftPacket(unsigned char *sender_mac, unsigned char* sender_ip, unsigned char *target_mac, unsigned char *target_ip, int ARPOP_CODE);
pcap_t* prepareConnection(char* interface);
int sendArpPacket(pcap_t *handle, Packet *packet);
int receiveArpPacket(pcap_t *handle, uint8_t mac[ETH_ALEN]);
void* threadSendArpPacket(void* tArgs);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const
u_char *pkt_data);
void* threadHandlePacket(void* tArgs);
char* read_file(char* filename);

#endif //C_ARP_SPOOF_H
