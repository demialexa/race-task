#include <stdio.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>


uint32_t isn, irn;

struct pseudo_header {
    uint32_t ph_src, ph_dst;
    uint8_t ph_pad, ph_ptcl;
    uint16_t ph_len;
};

enum {
    k_iphdr_len = sizeof(struct ip),
    k_tcphdr_len = sizeof(struct tcphdr),
    k_pshdr_len = sizeof(struct pseudo_header),
    k_dport = 1337
};

const char k_dst[] = "206.189.1.230";
const char k_src[] = "10.0.2.15";

#include <stdio.h>

// Usage:
//     hexDump(desc, addr, len, perLine);
//         desc:    if non-NULL, printed as a description before hex dump.
//         addr:    the address to start dumping from.
//         len:     the number of bytes to dump.
//         perLine: number of bytes on each output line.

void hexDump (
    const char * desc,
    const void * addr,
    const int len,
    int perLine
) {
    // Silently ignore silly per-line values.

    if (perLine < 4 || perLine > 64) perLine = 16;

    int i;
    unsigned char buff[perLine+1];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL) printf ("%s:\n", desc);

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0) printf ("  %s\n", buff);

            // Output the offset of current line.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.

        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.

    while ((i % perLine) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
    return(answer);
}

char *tcp(const char *data_ptr, size_t data_len, uint8_t flags, size_t *tcp_len) {
        *tcp_len = k_tcphdr_len + data_len;
    
    struct tcphdr th = {
        .th_sport = htons(12345),
        .th_dport = htons(k_dport),
        .th_seq = htonl(isn),
        .th_ack = htonl(irn),
        .th_x2 = 0,
        .th_off = k_tcphdr_len >> 2,
        .th_flags = flags,
        .th_win = htons(5480),
        .th_sum = 0,                    // later
        .th_urp = 0
    };

    struct pseudo_header ph = {
        .ph_src = inet_addr(k_src),
        .ph_dst = inet_addr(k_dst),
        .ph_pad = 0,
        .ph_ptcl = IPPROTO_TCP,
        .ph_len = htons(*tcp_len),
    };

    // derive checksum for tcp header
    char *ps_tcp_data = malloc(k_pshdr_len + *tcp_len);
    memcpy(ps_tcp_data, &ph, k_pshdr_len);
    memcpy(ps_tcp_data + k_pshdr_len, &th, k_tcphdr_len);
    memcpy(ps_tcp_data + k_pshdr_len + k_tcphdr_len, data_ptr, data_len);                                 // without trailing \0
    th.th_sum = csum((uint16_t*)ps_tcp_data, k_pshdr_len + *tcp_len);
    free(ps_tcp_data);

    // construct tcp segment
    char *tcp_ptr = malloc(*tcp_len);
    memcpy(tcp_ptr, &th, k_tcphdr_len);
    memcpy(tcp_ptr + k_tcphdr_len, data_ptr, data_len);
    return tcp_ptr;
}

char *ip(const char *data_ptr, size_t data_len, size_t *ip_len) {
    *ip_len = k_iphdr_len + data_len;
    struct ip ih = {
        .ip_v = 4,
        .ip_hl = k_iphdr_len >> 2,
        .ip_tos = 0x00,                         // b0001000 => low delay
        .ip_len = htons(*ip_len),
        .ip_id = htons(0x1234),
        .ip_off = htons(0 | (0 & IP_OFFMASK)),
        .ip_ttl = 255,
        .ip_p = IPPROTO_TCP,
        .ip_sum = 0,                            // later (consider .sum = 0)
        .ip_src = { inet_addr(k_src) },
        .ip_dst = { inet_addr(k_dst) }
    };


    ih.ip_sum = csum((uint16_t*)&ih, k_iphdr_len);
    char *ip_ptr = malloc(*ip_len);
    memcpy(ip_ptr, &ih, k_iphdr_len);
    memcpy(ip_ptr + k_iphdr_len, data_ptr, data_len);

    return ip_ptr;
}

char *datagram(const char *str_ptr, uint8_t flags, size_t *len) {
    size_t tcp_len, str_len = str_ptr ? strlen(str_ptr) : 0;
    char *tcp_ptr = tcp(str_ptr, str_len, flags, &tcp_len);
    char *datagram_ptr = ip(tcp_ptr, tcp_len, len);
    free(tcp_ptr);
    return datagram_ptr;
}

void handshake(int sock, struct sockaddr* to) {
    isn = rand(); 
    irn = 1;

    size_t syn_len, ack_len;
    char *syn = datagram(NULL, TH_SYN, &syn_len);
    isn++;
    char *ack = datagram(NULL, TH_ACK, &ack_len);
    char buf[1024];

    hexDump(NULL, syn, syn_len, 16);
    ssize_t b = sendto(sock, syn, syn_len, 0, to, sizeof(*to));
    printf("%ld\n", b);


    ssize_t resp = recv(sock, buf, sizeof(buf), 0);
    printf("%ld: %s\n", resp, buf);

    sleep(1);

    sendto(sock, ack, ack_len, 0, to, sizeof(*to));

    free(syn);
    free(ack);
}

void fin(int sock, struct sockaddr* to) {
    size_t fin_len;
    char *fin = datagram(NULL, TH_FIN, &fin_len);
    sendto(sock, fin, fin_len, 0, to, sizeof(*to));
    free(fin);
}

int main() {
    srand(time(NULL));
    char data[] = "POST /email-code/send/ HTTP/1.1\r\n"
"Host: 206.189.1.230:1337\r\n"
"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0\r\n"
"Accept: */*\r\n"
"Accept-Language: en-US,en;q=0.5\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Referer: http://206.189.1.230:1337/\r\n"
"Content-Type: application/x-www-form-urlencoded\r\n"
"Origin: http://206.189.1.230:1337\r\n"
"Content-Length: 7\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"email=a";
/*
    tmp = tcp(data, data_len, 0, &tcp_len);
    char *http = ip(tmp, tcp_len, &http_len);
    free(tmp);
*/
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = inet_addr(k_dst);
    to.sin_port = htons(k_dport);

    handshake(sock, (struct sockaddr*)&to);
    sleep(3);
    fin(sock, (struct sockaddr*)&to);
    return 0;
}