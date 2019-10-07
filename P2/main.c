/*
 * Samuel Carroll
 * 11477450
 * CptS 455 Intro to Networking
 * Project 1
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
#include <netinet/in.h>
#include <assert.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1
#define ARP  2

struct arp_hdr {
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

void ARP_SendReply(char interfaceName[], char IP_Add[])
{
    struct in_addr addr;
    struct arp_hdr hdr;
    struct ifreq if_idx, if_ifr, if_hwadd;
    struct sockaddr_ll sk_addr = {0};
    int recv_check = 0;
    char buf[BUF_SIZ] = {0};
    int sk_addr_size = sizeof(struct sockaddr_ll);

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
    sk_addr.sll_protocol = ETH_P_ARP;
    memcpy(sk_addr.sll_addr, broadcast_addr, ETHER_ADDR_LEN);

    hdr.ar_hrd = htons(ARPHRD_ETHER);
    hdr.ar_pro = htons(ETH_P_IP);
    hdr.ar_hln = ETH_ALEN;
    hdr.ar_pln = sizeof(in_addr_t);
    hdr.ar_op = htons(ARPOP_REQUEST);
    memset(&hdr.ar_tha, 0, sizeof(hdr.ar_tha));
    memcpy(&hdr.ar_tip, &addr.s_addr, sizeof(hdr.ar_tip));

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
    memcpy(&hdr.ar_sip, &((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr, sizeof(hdr.ar_sip));
    //printf("%lu\n", ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr);
    for(i = 0; i < ETH_ALEN; i++)
    {
        hdr.ar_sha[i] = ((uint8_t*)&if_hwadd.ifr_hwaddr.sa_data)[i];
        //printf("%hhx.", ((uint8_t*)&if_hwadd.ifr_hwaddr.sa_data)[i]);
    }
    //printf("\n%d\n", ((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr);
    printf("Sending ARP Request\n");
    if(sendto(sockfd, &hdr, sizeof(hdr), 0, (struct sockaddr*)&sk_addr, sizeof(sk_addr)) < 0)
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
                if(buf[i + 18])
                {
                    status = 1;
                }
            }
            
            if(status)
            {
                for(i = 0; i < ETH_ALEN; i++)
                {
                    if(i == (ETH_ALEN - 1))
                    {
                        printf("%hhx\n", ((struct arp_hdr*)buf)->ar_tha[i]);
                    }
                    else
                    {
                        printf("%hhx:", ((struct arp_hdr*)buf)->ar_tha[i]);
                    }
                }
                break;
            }
        }
    }
}

void send_message(char hw_addr[], char interfaceName[], char buf[]){

    int sockfd = 0, byte_sent = 0, len = 0, i = 0;
    struct ifreq if_idx, if_adr;
    struct sockaddr_ll sk_addr;
    int sk_addr_size = sizeof(struct sockaddr_ll);
    char sendbuf[BUF_SIZ];
    memset(sendbuf, 0, BUF_SIZ);
    struct ether_header *eth_head = (struct ether_header*)sendbuf;
    int head_len = sizeof(struct ether_header);
	printf("Send Message: %s\n%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n%s\n", interfaceName, hw_addr[0], hw_addr[1],hw_addr[2],hw_addr[3],hw_addr[4],hw_addr[5], buf);
    len = sizeof(struct ether_header) + strlen(buf);
    
    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket failed\n");
        exit(1);
    }

    // else
    // {
    //     printf("Success\n");
    // }
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interfaceName, IF_NAMESIZE - 1);
    if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    {
        perror("SIOCGIFINDEX\n");
        exit(1);
    }
    // else
    // {
    //     printf("Success\n");
    // }
    memset(&if_adr, 0, sizeof(struct ifreq));
    strncpy(if_adr.ifr_name, interfaceName, IF_NAMESIZE - 1);
    if(ioctl(sockfd, SIOCGIFHWADDR, &if_adr) < 0)
    {
        perror("SIOCGIFHWADDR\n");
        exit(1);
    }
    // else
    // {
    //     printf("Success\n");
    // }
    
    for(i = 0; i < ETH_ALEN; i++)
    {
        eth_head->ether_shost[i] = ((uint8_t*)&if_adr.ifr_hwaddr.sa_data)[i];
    }

    for(i = 0; i < ETH_ALEN; i++)
    {
        eth_head->ether_dhost[i] = hw_addr[i];
    }

    eth_head->ether_type = htons(ETH_P_ALL);

    memset(&sk_addr, 0, sk_addr_size);
    sk_addr.sll_ifindex = if_idx.ifr_ifindex;
    sk_addr.sll_halen = ETH_ALEN;
    sk_addr.sll_family = AF_PACKET;
    for(i = 0; i < ETH_ALEN; i++)
    {
        sk_addr.sll_addr[i] = hw_addr[i];
    }
    
    for(i = 0; i < len; i++)
    {
        sendbuf[head_len] = buf[i];
        head_len++;
    }

    if((byte_sent = sendto(sockfd, sendbuf, len, 0, (struct sockaddr*)&sk_addr, sk_addr_size)) < 0)
    {
        perror("Message send failure\n");
        exit(1);
    }
    else
    {
        printf("Message:\n%s\nsent %d bytes\n", &sendbuf[sizeof(struct ether_header)], byte_sent);
    }
    
}

void recv_message(char interfaceName[]){
    
    int sockfd = 0, recv_check = 0, hdr_size = sizeof(struct ether_header);
    char buf[BUF_SIZ];
    struct sockaddr sk_addr;
    int sk_addr_size = sizeof(struct sockaddr_ll);
    int i = 0;
    int sd;
    
    printf("Recv Message: %s\n", interfaceName);
    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket failed\n");
        exit(1);
    }
    if((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket failed\n");
        exit(1);
    }
    // else
    // {
    //     printf("Success\n");
    // }
    
    memset(buf, 0, BUF_SIZ);
    if((recv_check = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, (socklen_t*)&sk_addr_size)) < 0)
    {
        perror("Receive failed\n");
        exit(1);
    }
    else if(recv_check == 0)
    {
        perror("No bytes received\n");
        exit(1);
    }
    if(((struct ether_header*)buf)->ether_type == htons(ETH_P_ALL))
    {
        printf("%d bytes received successfully\n", recv_check);
        printf("Msg Received: %s\n", &buf[sizeof(struct ether_header)]);
    }
    else
    {
        struct ifreq if_add, if_hwadd, if_idx;

        memset(&if_idx, 0, sizeof(struct ifreq));
        strncpy(if_idx.ifr_name, interfaceName, IF_NAMESIZE - 1);
        if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        {
            perror("SIOCGIFINDEX\n");
            exit(1);
        }

        memset(&if_add, 0, sizeof(struct ifreq));
        strncpy(if_add.ifr_name, interfaceName, IFNAMSIZ - 1);
        if(ioctl(sockfd, SIOCGIFADDR, &if_add) < 0)
        {
            perror("SIOCGIFADDR");
        }

        memset(&if_hwadd, 0, sizeof(struct ifreq));
        strncpy(if_hwadd.ifr_name, interfaceName, IFNAMSIZ - 1);
        if(ioctl(sockfd, SIOCGIFHWADDR, &if_hwadd) < 0)
        {
            perror("SIOCGIFHWADDR");
        }
        //memcpy(&hdr.ar_sip, &((struct sockaddr_in *)&if_idx.ifr_addr)->sin_addr.s_addr, sizeof(hdr.ar_sip));
        struct arp_hdr *hdr = (struct arp_hdr*)buf;
        struct in_addr addr;
        struct sockaddr_ll sk_addr = {0};
        addr = *(struct in_addr*)(hdr->ar_tip);
        if(addr.s_addr == ((struct sockaddr_in *)&if_add.ifr_addr)->sin_addr.s_addr)
        {
            memset(&sk_addr, 0, sk_addr_size);
            for(i = 0; i < ETH_ALEN; i++)
            {
                //printf("%hhx.", ((uint8_t*)&if_hwadd.ifr_hwaddr.sa_data)[i]);
                hdr->ar_tha[i] = ((uint8_t*)&if_hwadd.ifr_hwaddr.sa_data)[i];
                sk_addr.sll_addr[i] = hdr->ar_sha[i];
            }
            sk_addr.sll_ifindex = if_idx.ifr_ifindex;
            sk_addr.sll_halen = ETH_ALEN;
            sk_addr.sll_family = AF_PACKET;
            sk_addr.sll_protocol = ETH_P_ARP;
            int bytes_sent = 0;
            printf("\nMatch!\n");
            if((bytes_sent = sendto(sd, (char*)hdr, sizeof(*hdr), 0, (struct sockaddr*)&sk_addr, sizeof(sk_addr))) < 0)
            {
                perror("sendto");
            }
        }
    }
    
    close(sockfd);
    // if(recv_check < sizeof(struct ether_header))
    // {
    //     printf("ARP Package\n");
    // }
    
}

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
    char IP_Add[20];
	memset(buf, 0, BUF_SIZ);
	
	int correct=0;
	if (argc > 1){
		if(strncmp(argv[1],"Send", 4)==0){
			if (argc == 5){
				mode=SEND; 
				sscanf(argv[3], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &hw_addr[0], &hw_addr[1], &hw_addr[2], &hw_addr[3], &hw_addr[4], &hw_addr[5]);
				strncpy(buf, argv[4], BUF_SIZ);
				correct=1;
				printf("  buf: %s\n", buf);
			}
            strncpy(interfaceName, argv[2], IFNAMSIZ);
		}
		else if(strncmp(argv[1],"Recv", 4)==0){
			if (argc == 3){
				mode=RECV;
				correct=1;
			}
            strncpy(interfaceName, argv[2], IFNAMSIZ);
		}
        else
        {
            assert(argc > 2);
            strncpy(interfaceName, argv[1], IFNAMSIZ);
            //inet_aton(argv[2], &IPhold);
            strcpy(IP_Add, argv[2]);
            mode = ARP;
            correct = 1;
        }
	 }
	 if(!correct){
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <DestHWAddr> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
        fprintf(stderr, "./455_proj2 <InterfaceName> <IP Address>");
		exit(1);
	 }
	//Do something here

	if(mode == SEND){
		send_message(hw_addr, interfaceName, buf);
	}
	else if (mode == RECV){
		recv_message(interfaceName);
	}
    else if(mode == ARP)
    {
        ARP_SendReply(interfaceName, IP_Add);
    }

	return 0;
}
