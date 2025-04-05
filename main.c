#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>

#define PACKET_SIZE 64
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

struct icmp_message {
    struct icmp_header hdr;
    union {
        struct {
            uint16_t identifier;
            uint16_t sequence_number;
            uint8_t payload[PACKET_SIZE - sizeof(struct icmp_header) - 2 * sizeof(uint16_t)];
        } echo;
        struct {
            uint32_t unused;
            uint8_t data[8];
        } error;
    } body;
};

unsigned short checksum(void* b, int len) {
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

typedef struct {
    int transmitted;
    int received;
    double min_time;
    double max_time;
    double total_time;
    double sq_total_time;
    char* hostname;
} PingStats;

double get_current_time_ms(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

void update_stats(PingStats* stats, double rtt){
    stats->received++;
    stats->total_time += rtt;
    stats->sq_total_time += rtt * rtt;
    if (rtt < stats->min_time) stats->min_time = rtt;
    if (rtt > stats->max_time) stats->max_time = rtt;
}

void print_stats(PingStats* stats) {
    printf("--- %s ping statistics ---\n", stats->hostname);
    printf("%d packets transmitted, %d packets received, %.0f%% packet loss\n",
           stats->transmitted, stats->received,
           stats->transmitted > 0 ? ((stats->transmitted - stats->received) * 100.0) / stats->transmitted : 0);

    if (stats->received > 0) {
        double avg_time = stats->total_time / stats->received;
        double stddev = (stats->sq_total_time / stats->received) - (avg_time * avg_time);
        stddev = (stddev > 0) ? sqrt(stddev) : 0;

        printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
               stats->min_time, avg_time, stats->max_time, stddev);
    }
}

void print_help() {
    printf("사용법: ft_ping [-v] [-?] <호스트 이름>\n");
    printf("옵션:\n");
    printf("  -v   상세 출력 (오류 포함)\n");
    printf("  -?   도움말 표시\n");
}

void* signal_handler_thread(void* arg) {
    PingStats* stats = (PingStats*) arg;
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);  // SIGINT를 감지할 시그널 세트 설정

    // SIGINT가 들어올 때까지 대기
    sigwait(&set, &sig);

    // SIGINT 발생 시 통계 출력
    print_stats(stats);
    free(stats);

    exit(0);
}

int main(int argc, char* argv[]) {
    int verbose = 0;
    char* hostname = NULL;

    for(int i = 1; i < argc; ++i){
        if(strcmp(argv[i], "-v") == 0){
            verbose = 1;
        }
        else if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else if (hostname == NULL) {
            hostname = argv[i];
        }
    }
    //예외처리

    printf("verbose mode: %d\n", verbose); // 디버깅 출력

    if(!hostname){
        printf("ft_ping: 호스트 이름을 입력하세요\n");
        print_help();
        return 1;
    }

    struct hostent* host = gethostbyname(hostname);
    if (host == NULL) {
        printf("ft_ping: 호스트 이름 변환 실패: %s\n", hostname);
        return 1;
    }

    struct in_addr** addr_list = (struct in_addr**) host->h_addr_list;
    char* target_ip = inet_ntoa(*addr_list[0]);

    printf("PING %s (%s): %lu data bytes", hostname, target_ip, sizeof(((struct icmp_message*)0)->body.echo.payload));
    if (verbose) {
        printf(", id 0x%04x = %d", getpid(), getpid());
    }
    printf("\n");

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("소켓 생성 실패");
        return 1;
    }
    int broadcast = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0){
        perror("브로드캐스트 옵션 설정 실패");
        close(sock);
        return 1;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(target_ip);

    // `PingStats`를 동적으로 할당
    PingStats* stats = (PingStats*)malloc(sizeof(PingStats));
    if (!stats) {
        perror("메모리 할당 실패");
        return 1;
    }
    stats->transmitted = 0;
    stats->received = 0;
    stats->min_time = 10000;
    stats->max_time = 0;
    stats->total_time = 0;
    stats->sq_total_time = 0;
    stats->hostname = hostname;  // hostname 저장

    pthread_t tid;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    pthread_create(&tid, NULL, signal_handler_thread, stats);

    int seq = 0;
    while (1) {
        double seq_start = get_current_time_ms();

        char packet[PACKET_SIZE];
        memset(packet, 0, PACKET_SIZE);
        struct icmp_message* icmp = (struct icmp_message*) packet;

        icmp->hdr.type = ICMP_ECHO_REQUEST;
        icmp->hdr.code = 0;
        icmp->body.echo.identifier = getpid();
        icmp->body.echo.sequence_number = seq;
        icmp->hdr.checksum = checksum(packet, PACKET_SIZE);

        double start_time = get_current_time_ms();
        sendto(sock, packet, PACKET_SIZE, 0, (struct sockaddr*) &dest, sizeof(dest));
        stats->transmitted++;

        double wait_start = get_current_time_ms();
        while (get_current_time_ms() - wait_start < 300) {
            fd_set readfds;
            struct timeval tv;
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);
            tv.tv_sec = 0;
            tv.tv_usec = 100000;

            int ret = select(sock + 1, &readfds, NULL, NULL, &tv);
            if (ret > 0 && FD_ISSET(sock, &readfds)) {
                char recv_packet[PACKET_SIZE];
                struct sockaddr_in from;
                socklen_t from_len = sizeof(from);

                int received = recvfrom(sock, recv_packet, PACKET_SIZE, 0, (struct sockaddr*) &from, &from_len);
                if (received > 0) {
                    double rtt = get_current_time_ms() - start_time;
                    update_stats(stats, rtt);
                    struct icmp_message* recv_icmp = (struct icmp_message*) (recv_packet + 20);
                    int ttl = recv_packet[8];

                    if (recv_icmp->hdr.type == ICMP_ECHO_REPLY) {
                        if (recv_icmp->body.echo.identifier == getpid()) {
                            printf("%lu bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
                                   sizeof(struct icmp_message), inet_ntoa(from.sin_addr), seq, ttl, rtt);
                        }
                        else {
                            if (verbose) {
                                printf("다른 프로세스의 응답 무시됨 (identifier=%d)\n", recv_icmp->body.echo.identifier);
                            }
                        }

                    }
                    else if (recv_icmp->hdr.type == ICMP_DEST_UNREACH) {
                        const char* reason = NULL;
                        switch (recv_icmp->hdr.code) {
                            case 0:
                                reason = "Destination Not Unreachable";
                                break;
                            case 1:
                                reason = "Destination Host Unreachable";
                                break;
                            case 2:
                                reason = "Protocol Unreachable";
                                break;
                            case 3:
                                reason = "Port Unreachable";
                                break;
                            default:
                                reason = "Destination Unreachable (Unknown reason)";
                                break;
                        }
                        printf("From %s icmp_seq=%d %s\n", inet_ntoa(from.sin_addr), seq, reason);
                    }
                    else if (recv_icmp->hdr.type == ICMP_TIME_EXCEEDED) {
                        if (verbose) {
                            printf("오류: Time Exceeded (코드 %d)", recv_icmp->hdr.code);
                        }
                    }
                }
            }
        }
        double elapsed = get_current_time_ms() - seq_start;
        if (elapsed < 1000) {
            usleep((useconds_t) (1000.0 - elapsed) * 1000);
        }

    }
    close(sock);
    return 0;
}
