#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

#define PACKET_SIZE 64

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

    for (int sum = 0; len > 1; len -= 2) {
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

int main(int argc, char* argv[]){
    if(argc != 2){
        printf("사용법: %s <호스트 이름>\n", argv[0]);
        return 1;
    }

    char* hostname = argv[1];
    struct hostent* host = gethostbyname(hostname);
    if (host == NULL) {
        printf("호스트 이름 변환 실패: %s\n", hostname);
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

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(target_ip);

    char packet[PACKET_SIZE];
    struct icmphdr * icmp = (struct icmphdr*) packet;
    icmp->type = 8;
    icmp->code = 0;
    icmp->id = getpid();
    icmp->sequence = 1;
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, PACKET_SIZE);

    int sent = sendto(sock, packet, PACKET_SIZE, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (sent < 0) {
        perror("패킷 전송 실패");
        close(sock);
        return 1;
    }
    printf("ICMP 에코 요청 전송 완료 (%d 바이트)\n", sent);

    close(sock);
    return 0;
}