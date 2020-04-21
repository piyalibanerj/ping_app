/**
 * @ping
 * @author  Piyali Banerjee
 * @version 1.0
 *
 * @section DESCRIPTION
 *
 * Ping CLI application for MacOS or Linux. It requires root permission. 
 * The CLI app accepts a hostname or an IP address as its argument,
 * sends ICMP "echo requests" in a loop 
 * to the target while receiving "echo reply" messages. 
 * It reports loss and RTT times for each sent message.
 * It allows to set TTL as an argument and report the corresponding "time exceeded” ICMP messages.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <setjmp.h>
#include <errno.h>
#include <time.h>

#define PING_PACKET_SIZE 56
#define TRUE 1
#define FALSE 0

#define PACKET_SIZE     4096
#define TIMEOUT   1
#define PING_SLEEP_RATE 1000000

#ifndef SOL_IP
    #define SOL_IP IPPROTO_IP
#endif

char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];

uint16_t pid;
struct sockaddr_in dest_addr; // to store the information of the host to ping for ipv4
struct sockaddr_in6 dest_addr6; // to store the information of the host to ping for ipv6
struct sockaddr_in from; // to store the information which has been received for ping
struct sockaddr_in6 from6; // to store the information which has been received for ping
int sockfd; // socket file descriptor
int ping_loop; // to control the ping loop
//int ttl_val = 64; // time to live value

int verbose = TRUE;

/**
* checksum function
* @param  buf packet buffer 
* @param  len length of the packet
* @return ~sum checksum value
*
* @section DESCRIPTION
*
* calculates checksum of the packet 
* Reference - https://www.csee.usf.edu/~kchriste/tools/checksum.c
*/
unsigned short checksum(unsigned short *buf, int len) 
{    
    unsigned int sum=0; 
    while(len > 1){
        sum += *buf++;
        len -= 2;
    }

    // Add left-over byte, if any
    if (len > 0)
        sum += *(unsigned char*)buf;

    // Fold 32-bit sum to 16 bits
    while (sum>>16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return(~sum);
}

/**
* interrupt handler function
* @param  dummy value for interrupt
*
* @section DESCRIPTION
*
* sets the value of ping_loop variable to false
*/
void intHandler(int dummy) 
{ 
    ping_loop=FALSE; 
}

/**
* pack function
* @param  pack_no packet number
* @return packsize packet size
*
* @section DESCRIPTION
*
* creates the icmp ECHO packet for ping request
*/
int pack(int pack_no)
{
    int packsize;

    struct icmp *icmp;

    icmp = (struct icmp*)sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    icmp->icmp_id = pid;

    // store the packet checksum
    packsize = 8 + PING_PACKET_SIZE;

    // store the packet checksum
    icmp->icmp_cksum = checksum((unsigned short*)icmp, packsize); 

    return packsize;
}

/**
* pack function
* @param  buf packet received
* @param  len length of the packet
* @param  rtt RTT value for the packet
* @return 1 SUCCESS, -1 FAILURE
*
* @section DESCRIPTION
*
* extracts the IP, ICMP packet and echo information from the received datagram from host
*/
int unpack(char *buf, int len, long double rtt)
{
    // received ping has ICMP message with type, code and first 8 bytes of IP datagram causing error
    int iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    
    ip = (struct ip*)buf;
    iphdrlen = ip->ip_hl << 2; 
    icmp = (struct icmp*)(buf + iphdrlen);
    len -= iphdrlen; // removing IP header length

    // for invalid ICMP packet size
    if (len < 8){
        printf("ICMP packets\'s length is less than 8\n");
        return  - 1;
    } 

    // for ICMP ECHO reply messages
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)){
        if(verbose)
            printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%Lf ms\n", len, inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
    } else if(icmp->icmp_type == 3){
        // report the "destination host unreachable" ICMP messages
        printf("Reply from %s: Destination host unreachable. \n", inet_ntoa(from.sin_addr));
    } else if(icmp->icmp_type == 11){
        // report the "time exceeded” ICMP messages
        printf("ICMP: time exceeded (time to live) sent to %s: \n", inet_ntoa(from.sin_addr));
    } else
        return  - 1;

    return 1;
}

/**
* start ping function
*
* @section DESCRIPTION
*
* sends/receives ping in an infinite loop
*/
void start_ping(int ttl_val)
{
    int packsize, flag, len;
    float loss;
    int sent_count = 0, recv_count = 0;
    socklen_t fromlen;
    
    struct timespec time_start, time_end, tfs, tfe; // for caluculating the RTT and total time elapsed values 
    long double rtt_msec=0, total_msec=0; // initializing rtt and total time variables 
    struct timeval tv_out; // for timeout
    tv_out.tv_sec = TIMEOUT; // periodic delay to emit requests 
    tv_out.tv_usec = 0; 
    clock_gettime(CLOCK_MONOTONIC, &tfs); // get the start time
    // set socket options at ip to TTL and value to 64 
    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0){ 
        printf("Setting socket options to TTL failed!\n"); 
        return; 
    } else { 
        printf("Socket has been set to TTL value %d \n", ttl_val); 
    } 

    // setting timeout of recv setting, if it is not set, receive will be waiting forever
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out)); 
    
    ping_loop = TRUE;

    // send/receive icmp packet in an infinite loop 
    while(ping_loop){
        flag = TRUE;
        packsize = pack(++sent_count); // to create the icmp ECHO request
        usleep(PING_SLEEP_RATE);

        //send packet 
        clock_gettime(CLOCK_MONOTONIC, &time_start); // start time for RTT calculation
        if(sendto(sockfd, sendpacket, packsize, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0){ 
            perror("sendto failed!\n"); 
            flag=FALSE; 
        }
        
        //receive packet 
        fromlen = sizeof(from);
        if((len = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr*)&from, &fromlen)) < 0 && sent_count>1){ 
            perror("recvfrom error!\n"); 
            continue;
        } else {
            clock_gettime(CLOCK_MONOTONIC, &time_end); // end time for RTT calculation
            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0;
            rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed; 
            
            // if packet was not sent, don't receive 
            if(flag){
                // to unpack the values received from host
                if (unpack(recvpacket, len, rtt_msec) ==  - 1)
                    continue;

                recv_count++;    
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &tfe); // end time for ping 
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0; 
      
    total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed; 
    loss = 100 - ((recv_count * 200 + sent_count) / (sent_count * 2)); // packet loss count
    // print the statistics 
    printf("\n=== ping statistics ===\n"); 
    printf("\n%d packets sent, %d packets received, %f percent packet loss. Total time: %Lf ms.\n\n", sent_count, recv_count, loss, total_msec); 
    close(sockfd);
}

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list (first argument ip/hostname, second argument ttl)
 * @return 0 EXIT_SUCCESS
 * 
 * @section DESCRIPTION
 * driver code for the ping application
 */
int main(int argc, char **argv)
{
    int size, ttl_val; 
    struct hostent *he; // for storing the host information
    int flag_hostname = 0; // flag to check if argument is hostname or ip address
    char str[INET_ADDRSTRLEN];
    char ipstr[INET6_ADDRSTRLEN];
	char host[1024];
	char service[20];
    // check if number of arguments received is correct
    if(argc < 3) {
		printf("Usage:%s [ip/hostname] [ttl] \n", argv[0]);
		exit(1);
	}

    printf("Arguments received: %s, %s \n", argv[1], argv[2]);

    ttl_val = atoi(argv[2]);

    // create raw socket for ICMP packets, need root permission
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        perror("socket error");
        exit(1);
    }
    
    setuid(getuid());

    // set socket receive buffer size
    size = 60 * 1024;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET; // host byte order
    if(inet_aton(argv[1], &dest_addr.sin_addr) == 0){
        // get the host information
        if ((he=gethostbyname(argv[1])) == NULL) {
            perror("gethostbyname");
            exit(1);
        }
        memcpy((char*) &dest_addr.sin_addr, he->h_addr, he->h_length);
        flag_hostname = 1;
    } else {
        // get hostname from ip address
        inet_ntop(AF_INET, &dest_addr.sin_addr, str, INET_ADDRSTRLEN);
	    if (getnameinfo((struct sockaddr *)&dest_addr, sizeof(dest_addr), host, sizeof(host), service, sizeof(service), 0)){
		    perror("getnameinfo failed");
	    }
	    printf("Hostname of the given ip address %s\n", host);
    }
	
    // get the process id
    pid = getpid();
    printf("Process id - %u \n", pid);

    if(verbose){
        if(flag_hostname){
            printf("PING %s(%s): %d bytes data in ICMP packets.\n", argv[1], inet_ntoa(dest_addr.sin_addr), PING_PACKET_SIZE);
        } else {
            printf("PING %s(%s): %d bytes data in ICMP packets.\n", argv[1], host, PING_PACKET_SIZE);
        }
    }

    signal(SIGINT, intHandler); //for catching interrupt when user wants to stop receiving ping

    start_ping(ttl_val); // start/stop receiving ping from host

    return 0;
}
