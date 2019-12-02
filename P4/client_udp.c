#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define SERVER_PORT 5432
#define MAX_LINE 88

struct sliding_window{
    uint16_t sequence;
};

int main(int argc, char * argv[])
{
    FILE *fp;
    struct hostent *hp;
    struct sockaddr_in sin, rin;
    struct timeval tv;
    char *host;
    char *fname;
    char buf[MAX_LINE], recv[MAX_LINE];
    int s;
    int slen, len;
    struct sliding_window *SW = (struct sliding_window*)buf;
    struct sliding_window *test = (struct sliding_window*)recv;
    int SWsize = sizeof(SW);

    if (argc==3) {
        host = argv[1];
        fname= argv[2];
    }
    else {
        fprintf(stderr, "Usage: ./client_udp host filename\n");
        exit(1);
    }
    /* translate host name into peer’s IP address */
    hp = gethostbyname(host);
    if (!hp) {
        fprintf(stderr, "Unknown host: %s\n", host);
        exit(1);
    }

    fp = fopen(fname, "r");
    if (fp==NULL){
        fprintf(stderr, "Can't open file: %s\n", fname);
        exit(1);
    }

    /* build address data structure */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
    sin.sin_port = htons(SERVER_PORT);

    /* build address data structure */
    bzero((char *)&rin, sizeof(rin));
    rin.sin_family = AF_INET;
    rin.sin_addr.s_addr = INADDR_ANY;
    rin.sin_port = htons(SERVER_PORT);

    /* active open */
    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket");
        exit(1);
    }

    // if ((bind(s, (struct sockaddr *)&rin, sizeof(rin))) < 0) {
    //     perror("simplex-talk: bind");
    //     exit(1);
    // }

    tv.tv_sec = 0;
    tv.tv_usec = 1500;

    if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0){
        perror("SetSockOpt Error\n");
    }

    SW->sequence = 1;

    socklen_t sock_len= sizeof sin;

    /* main loop: get and send lines of text */
    while(fgets(&buf[SWsize], 80, fp) != NULL){
        slen = strlen(&buf[SWsize]);
        buf[slen + SWsize] ='\0';
        if(sendto(s, buf, slen+1 + SWsize, 0, (struct sockaddr *)&sin, sock_len)<0){
            perror("SendTo Error\n");
            exit(1);
        }
        // while(len = recvfrom(s, recv, sizeof(recv), 0, (struct sockaddr *)&rin, &sock_len) != -2)
        // {
        //     printf("%d %d %s\n", SW->sequence, test->sequence, (char*)&recv[SWsize]);
        //     if(len > 0)
        //     {
        //         if(SW->sequence == test->sequence)
        //         {
        //             SW->sequence++;
        //             break;
        //         }
        //     }
        //     else
        //     {
        //         if(sendto(s, buf, slen+1 + SWsize, 0, (struct sockaddr *)&sin, sock_len)<0){
        //             perror("SendTo Error\n");
        //             exit(1);
        //         }
        //     }
        // }
    }
    *buf = 0x02;    
        if(sendto(s, buf, 1, 0, (struct sockaddr *)&sin, sock_len)<0){
        perror("SendTo Error\n");
        exit(1);
    }
    fclose(fp);
}
