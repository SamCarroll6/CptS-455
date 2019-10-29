/*
 * Samuel Carroll
 * 11477450
 * CptS 455 Intro to Networking
 * Project 3
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1

struct arp_hdr {
    uint16_t       ar_typ; // 2 bytes
    uint16_t       ar_hrd; // 2 bytes
    uint16_t       ar_pro; // 2 bytes 
    unsigned char  ar_hln; // 1 byte
    unsigned char  ar_pln; // 1 byte
    uint16_t       ar_op; // 2 bytes
    unsigned char  ar_sha[6]; // 6 bytes
    unsigned char  ar_sip[4]; // 6 bytes
    unsigned char  ar_tha[6]; // 6 bytes
    unsigned char  ar_tip[4]; // 6 bytes
};

struct arp_hdr* ARP_SendReply(char interfaceName[], char IP_Add[]);

unsigned int get_netmask(char interfacename[], int sockfd)
{
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interfacename, IFNAMSIZ-1);
    if(ioctl(sockfd, SIOCGIFNETMASK, &if_idx) == -1)
    {
        perror("ioctl():");
    }
    return ((struct sockaddr_in *)&if_idx.ifr_netmask)->sin_addr.s_addr;
}

unsigned int get_ip_saddr(char interfacename[], int sockfd)
{
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interfacename, IFNAMSIZ-1);
    if(ioctl(sockfd, SIOCGIFADDR, &if_idx) == -1)
    {
        perror("SIOCGIFADDR");
    }
    return ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr;
}

void send_message(char hw_addr[], char interfaceName[], char IP_Dst[], char IP_Rout[], char sendbuf[]){
    // TODO Send Message
    int sockfd, i, count = 0;
    int sk_addr_size = sizeof(struct sockaddr_ll);
    unsigned int ip_saddr, netmask; 
    struct in_addr DstAdd, RoutAdd;
    char h1[20], h2[20];
    struct arp_hdr* RoutHW;
    char buf[BUF_SIZ];
    struct sockaddr_ll sk_addr;
    struct ifreq if_idx;
    struct ip* iphdr = (struct ip*)buf;
    /*
     * Conversion:
     *  Change provided IP's to struct in_addr
     *  values to make them more manageable.  
     */
    inet_aton(IP_Dst, &DstAdd);
    inet_aton(IP_Rout, &RoutAdd);

    /*
     * Open Socket:
     *  Open socket for type ETH_P_IP 
     */

    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
        perror("socket failed\n");
        exit(1);
    }


    /*
     * SRC IP and NetMask:
     *  Get and check the SRC hosts
     *  IP address and netmask to use for comparison later.
     */
    ip_saddr = get_ip_saddr(interfaceName, sockfd);
    netmask = get_netmask(interfaceName, sockfd);

    printf("ip_saddr = %s\n", inet_ntoa(*(struct in_addr*)&ip_saddr));
    printf("netmask = %s\n", inet_ntoa(*(struct in_addr*)&netmask));
    printf("ip_saddr = %d\nnetmask = %d\n", ip_saddr, netmask);



    /*
     * ARP Section:  
     *   get hw address of router or dst
     *   depending on if the destination 
     *   is in the same subnet as source. 
     */
    RoutHW = ARP_SendReply(interfaceName, IP_Rout);
    for(i = 0; i < ETH_ALEN; i++)
    {
        if(i == (ETH_ALEN - 1))
        {
            printf("%hhx\n", RoutHW->ar_sha[i]);
        }
        else
        {
            printf("%hhx:", RoutHW->ar_sha[i]);
        }
    }


    /*
     * sockaddr_ll Set:
     *  Set the values for sockaddr_ll to be
     *  passed in the send function later on. 
     */
    memset(&sk_addr, 0, sk_addr_size);

    sk_addr.sll_family = AF_PACKET;
    sk_addr.sll_protocol = ETH_P_IP;

    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interfaceName, IF_NAMESIZE - 1);
    if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    {
        perror("SIOCGIFINDEX\n");
        exit(1);
    }
    sk_addr.sll_ifindex = if_idx.ifr_ifindex;

    sk_addr.sll_halen = ETH_ALEN;
    for(count = 0; count < ETH_ALEN; count++)
    {
        sk_addr.sll_addr[count] = RoutHW->ar_sha[count];
    }
}

void recv_message(char interfaceName[]){
    
    int sockfd = 0, recv_check = 0, hdr_size = sizeof(struct ether_header);
    char buf[BUF_SIZ];
    struct sockaddr sk_addr;
    int sk_addr_size = sizeof(struct sockaddr_ll);
    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
        perror("socket failed\n");
        exit(1);
    }
    // else
    // {
    //     printf("Success\n");
    // }
    while(1)
    {
        printf("Recv Message: %s\n", interfaceName);
        memset(buf, 0, BUF_SIZ);
        if((recv_check = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, (socklen_t*)&sk_addr_size)) < 0)
        {
            perror("Receive failed\n");
            exit(1);
        }
        else if(recv_check == 0)
        {
            printf("No bytes received\n");
        }
        else
        {
            printf("%d bytes received successfully\n", recv_check);
            printf("Msg Received: %s\n", &buf[sizeof(struct ether_header)]);
        }
    }   
}

int main(int argc, char *argv[])
{
	int mode,i = 0;
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
    char IP_Rout[20], IP_Dst[20];
	memset(buf, 0, BUF_SIZ);
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0){
			if (argc == 6){
				mode=SEND; 
                strcpy(IP_Dst, argv[3]);
                strcpy(IP_Rout, argv[4]);
				strncpy(buf, argv[5], BUF_SIZ);
				correct=1;
				printf("\nbuf: %s\nIPD = %s IPR = %s\n", buf, IP_Dst, IP_Rout);
			}
		}
		else if(strncmp(argv[1],"Recv", 4)==0){
			if (argc == 3){
				mode=RECV;
				correct=1;
			}
		}
		strncpy(interfaceName, argv[2], IFNAMSIZ);
	 }
	 if(!correct){
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <Dest IP> <Router IP> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	 }
	//Do something here

	if(mode == SEND){
		send_message(hw_addr, interfaceName, IP_Dst, IP_Rout, buf);
	}
	else if (mode == RECV){
		recv_message(interfaceName);
	}

	return 0;
}

struct arp_hdr* ARP_SendReply(char interfaceName[], char IP_Add[])
{
    struct in_addr addr;
    //struct arp_hdr hdr;
    struct ifreq if_idx, if_ifr, if_hwadd;
    struct sockaddr_ll sk_addr = {0};
    int recv_check = 0;
    unsigned char buf[BUF_SIZ] = {0};
    unsigned char sendbuf[BUF_SIZ] = {0xff,0xff,0xff,0xff,0xff,0xff};
    int sk_addr_size = sizeof(struct sockaddr_ll);
    struct arp_hdr *hdr = (struct arp_hdr*)&sendbuf[12], *rethdr;

    const unsigned char broadcast_addr[] = {0xff,0xff,0xff,0xff,0xff,0xff};

    int sockfd = 0, i = 0, sd = 0;
    inet_aton(IP_Add, &addr);
    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        perror("socket failed\n");
        exit(1);
    }

    if((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket failed\n");
        exit(1);
    }

    memset(&if_ifr, 0, sizeof(struct ifreq));
    strncpy(if_ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
    if(ioctl(sockfd, SIOCGIFINDEX, &if_ifr) < 0)
    {
        perror("SIOCGIFINDEX");
    }

    sk_addr.sll_ifindex = if_ifr.ifr_ifindex;
    sk_addr.sll_family = AF_PACKET;
    sk_addr.sll_halen = ETH_ALEN;
    sk_addr.sll_protocol = htons(ETH_P_ALL);
    sk_addr.sll_pkttype = ETH_P_ARP;
    memcpy(sk_addr.sll_addr, broadcast_addr, ETHER_ADDR_LEN);

    hdr->ar_typ = 0x0608;
    hdr->ar_hrd = htons(ARPHRD_ETHER);
    hdr->ar_pro = htons(ETH_P_IP);
    hdr->ar_hln = ETH_ALEN;
    hdr->ar_pln = sizeof(in_addr_t);
    hdr->ar_op =  htons(ARPOP_REQUEST);
    memset(&(hdr->ar_tha), 0xff, sizeof(hdr->ar_tha));
    memcpy(&(hdr->ar_tip), &addr.s_addr, sizeof(hdr->ar_tip));

    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interfaceName, IFNAMSIZ - 1);
    if(ioctl(sockfd, SIOCGIFADDR, &if_idx) < 0)
    {
        perror("SIOCGIFADDR");
    }

    memset(&if_hwadd, 0, sizeof(struct ifreq));
    strncpy(if_hwadd.ifr_name, interfaceName, IFNAMSIZ - 1);
    if(ioctl(sockfd, SIOCGIFHWADDR, &if_hwadd) < 0)
    {
        perror("SIOCGIFHWADDR");
    }

    //printf("\n%d\n", ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr);
    memcpy(&(hdr->ar_sip), &((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr, sizeof(hdr->ar_sip));
    //printf("%lu\n", ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr);
    for(i = 0; i < ETH_ALEN; i++)
    {
        hdr->ar_sha[i] = ((uint8_t*)&if_hwadd.ifr_hwaddr.sa_data)[i];
        sendbuf[i+6] = ((uint8_t*)&if_hwadd.ifr_hwaddr.sa_data)[i];
        //printf("%hhx.", ((uint8_t*)&if_hwadd.ifr_hwaddr.sa_data)[i]);
    }
    //printf("\n%d\n", ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr);
    printf("Sending ARP Request\n");
    if(sendto(sockfd, sendbuf, 42, 0, (struct sockaddr*)&sk_addr, sizeof(sk_addr)) < 0)
    {
        perror("sendto");
    }
    printf("Waiting for response\n");
    while(1)
    {
        if((recv_check = recvfrom(sd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, (socklen_t*)&sk_addr_size)) < 0)
        {
            perror("Receive failed\n");
            exit(1);
        }
        else if(recv_check == 0)
        {
            perror("No bytes received\n");
            exit(1);
        }
        else
        {
            // struct in_addr *hold = {0};
            // hold = &(((struct arp_hdr*)buf)->ar_tip);
            // printf("%s\n", inet_ntoa(*hold));
            
            int status = 0;
            for(i = 0; i < ETH_ALEN; i++)
            {
                if(((struct arp_hdr*)&buf[12])->ar_tha[i] != 0xff)
                {
                    status = 1;
                }
            }
            if((((struct arp_hdr*)&buf[12])->ar_tha[0] == 0xfe) && (((struct arp_hdr*)&buf[12])->ar_tha[1] == 0x80))
            {
                status = 0;
            }
            if(status)
            {
               /* for(i = 0; i < ETH_ALEN; i++)
                {
                    if(i == (ETH_ALEN - 1))
                    {
                        printf("%hhx\n", ((struct arp_hdr*)&buf[12])->ar_sha[i]);
                    }
                    else
                    {
                        printf("%hhx:", ((struct arp_hdr*)&buf[12])->ar_sha[i]);
                    }
                }
                */
                printf("Returning\n");
                rethdr = ((struct arp_hdr*)&buf[12]);
                return rethdr;
            }
        }
    }
}