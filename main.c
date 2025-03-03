#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#define PACKET_SIZE 64
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define PING_COUNT 4

struct icmphdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short sequence;
};

unsigned short checksum(void* b, int len){
    unsigned short* buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char*) buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

void print_help(){
    printf("사용법: ft_ping [-v] [-?] <호스트 이름>\n");
    printf("옵션:\n");
    printf("  -v   상세 출력 (오류 포함)\n");
    printf("  -?   도움말 표시\n");
}

int main(int argc, char* argv[]){
    int opt, verbose = 0;
    while ((opt = getopt(argc, argv, "v?")) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            case '?':
                print_help();
                return 0;
            default:
                print_help();
                return 1;
        }
    }

    if (optind >= argc) {
        printf("ft_ping: 호스트 이름을 입력하세요\n");
        print_help();
        return 1;
    }

    char* hostname = argv[optind];
    struct hostent* host = gethostbyname(hostname);
    if (host == NULL) {
        printf("ft_ping: 호스트 이름 변환 실패: %s\n", hostname);
        return 1;
    }

    struct in_addr** addr_list = (struct in_addr **)host->h_addr_list;
    char* target_ip = inet_ntoa(*addr_list[0]);
    printf("Ping 보낼 대상: %s (%s)\n", hostname, target_ip);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("소켓 생성 실패");
        return 1;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(target_ip);

    int sent_count = 0, recv_count = 0;
    double total_rtt = 0.0;

    for(int i = 0; i < PING_COUNT; ++i) {

        char packet[PACKET_SIZE];
        memset(packet, 0, PACKET_SIZE);
        struct icmphdr* icmp = (struct icmphdr*) packet;
        icmp->type = ICMP_ECHO_REQUEST;
        icmp->code = 0;
        icmp->id = getpid();
        icmp->sequence = i;
        icmp->checksum = checksum(packet, PACKET_SIZE);

        struct timeval start, end;
        gettimeofday(&start, NULL);

        int sent = sendto(sock, packet, PACKET_SIZE, 0, (struct sockaddr*) &dest, sizeof(dest));
        if (sent < 0) {
            perror("ft_ping: 패킷 전송 실패");
            close(sock);
            continue;
        }
        sent_count++;

        char recv_packet[PACKET_SIZE];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int received = recvfrom(sock, recv_packet, PACKET_SIZE, 0, (struct sockaddr*) &from, &from_len);
        if (received < 0) {
            printf("ft_ping: %d bytes to %s: seq=%d timeout\n", PACKET_SIZE, hostname, icmp->sequence);
            sleep(1);
            continue;
        }

        gettimeofday(&end, NULL);

        struct icmphdr* recv_icmp = (struct icmphdr*) (recv_packet + 20);
        if (recv_icmp->type == ICMP_ECHO_REPLY && recv_icmp->id == icmp->id) {
            double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                         (end.tv_usec - start.tv_usec) / 1000.0;
            printf("%d bytes from %s: seq=%d time=%.2f ms\n",
                   received, inet_ntoa(from.sin_addr), recv_icmp->sequence, rtt);
            recv_count++;
            total_rtt += rtt;
        }
        else if (verbose){
            printf("ft_ping: %d bytes from %s: type=%d code=%d seq=%d\n",
                   received, hostname, recv_icmp->type, recv_icmp->code, recv_icmp->sequence);
        }
        sleep(1);
    }

    printf("\n--- %s ft_ping 통계 ---\n", hostname);
    printf("전송: %d, 수신: %d, 손실: %d%%, 평균 시간: %.2f ms\n",
           sent_count, recv_count,
           sent_count ? ((sent_count - recv_count) * 100 / sent_count) : 0,
           recv_count ? (total_rtt / recv_count) : 0.0);

    close(sock);
    return 0;
}