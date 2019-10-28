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

#define BUF_SIZ		65536
#define SEND 0
#define RECV 1

void send_message(char hw_addr[], char interfaceName[], char buf[]){
    // TODO Send Message
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
        printf("No bytes received\n");
    }
    else
    {
        printf("%d bytes received successfully\n", recv_check);
        printf("Msg Received: %s\n", &buf[sizeof(struct ether_header)]);
    }
    
}

int main(int argc, char *argv[])
{
	int mode;
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
