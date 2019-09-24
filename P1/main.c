#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1

void send_message(char hw_addr[], char interfaceName[], char buf[]){

    int sockfd = 0, byte_sent = 0, len = 0, i = 0;
    struct ifreq if_idx, if_adr;
    struct sockaddr_ll sk_addr;
    int sk_addr_size = sizeof(struct sockaddr_ll);
    char sendbuf[BUF_SIZ];
	printf("Send Message: %s\n%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n%s\n", interfaceName, hw_addr[0], hw_addr[1],hw_addr[2],hw_addr[3],hw_addr[4],hw_addr[5], buf);
    len = sizeof(struct ether_header);

    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket failed\n");
    }
    else
    {
        printf("Success\n");
    }
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interfaceName, IF_NAMESIZE - 1);
    if(ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    {
        perror("SIOCGIFINDEX\n");
    }
    else
    {
        printf("Success\n");
    }
    memset(&if_adr, 0, sizeof(struct ifreq));
    strncpy(if_adr.ifr_name, interfaceName, IF_NAMESIZE - 1);
    if(ioctl(sockfd, SIOCGIFHWADDR, &if_adr) < 0)
    {
        perror("SIOCGIFHWADDR\n");
    }
    else
    {
        printf("Success\n");
    }
    
    memset(&sk_addr, 0, sk_addr_size);
    sk_addr.sll_ifindex = if_idx.ifr_ifindex;
    sk_addr.sll_halen = ETH_ALEN;

    for(i = 0; i < ETH_ALEN; i++)
    {
        sk_addr.sll_addr[i] = hw_addr[i];
    }
    
    len = strlen(buf);
    for(i = 0; i < len; i++)
    {
        sendbuf[i] = buf[i];
    }
    if((byte_sent = sendto(sockfd, sendbuf, len, 0, (struct sockaddr*)&sk_addr, sk_addr_size)) < 0)
    {
        perror("Message send failure\n");
    }
    else
    {
        printf("Message:\n%s\nsent %d bytes\n", sendbuf, byte_sent);
    }
    
}

void recv_message(char interfaceName[]){
    
    int sockfd = 0, recv_check = 0, hdr_size = sizeof(struct ether_header);
    char buf[BUF_SIZ];
    struct sockaddr sk_addr;
    int sk_addr_size = sizeof(struct sockaddr_ll);
    printf("Recv Message: %s\n", interfaceName);
    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket failed\n");
    }
    else
    {
        printf("Success\n");
    }
    
    if((recv_check = recvfrom(sockfd, buf, BUF_SIZ, 0, (struct sockaddr*)&sk_addr, (socklen_t*)&sk_addr_size)) < 0)
    {
        perror("Receive failed\n");
    }
    else if(recv_check == 0)
    {
        printf("No bytes received\n");
    }
    else
    {
        printf("%d bytes received successfully\n", recv_check);
        printf("Msg Received: %s\n", buf);
    }
    
}

int main(int argc, char *argv[])
{
	int mode;
	char hw_addr[6];
	char interfaceName[IFNAMSIZ];
	char buf[BUF_SIZ];
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
		fprintf(stderr, "./455_proj2 Send <InterfaceName>  <DestHWAddr> <Message>\n");
		fprintf(stderr, "./455_proj2 Recv <InterfaceName>\n");
		exit(1);
	 }
	//Do something here

	if(mode == SEND){
		send_message(hw_addr, interfaceName, buf);
	}
	else if (mode == RECV){
		recv_message(interfaceName);
	}

	return 0;
}
