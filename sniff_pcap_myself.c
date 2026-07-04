#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>

// packet = [Ethernet Header] [IP Header][TCP/UDP Hedaer][DATA]
//Ehernet Header = 14byte 고정
struct ethheader {
	u_char ether_dhost[6]; //dest host addr
	u_char ether_shost[6];//src host addr
	u_short ether_type; //protocoltype
};

//IP header의 길이는 가변적이기에 ipheader_len을 읽는 게 중요
struct ipheader {
	unsigned char iph_ihl : 4, iph_ver : 4; //IP header length, IP version
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag : 3, iph_offset : 13;
	unsigned char iph_ttll;
	unsigned char iph_protocol;
	unsigned short int iph_checksum;
	struct in_addr iph_sourceip;
	struct in_addr iph_destip;
};

struct tcpheader{
	u_short tcp_sport; //source port
	u_short tcp_dport; //destination port
	u_int tcp_seq; //sequence num
	u_int tcp_ack; //ack - 긍정 응답
	u_char tcp_offx2;
#define TH_OFF(th) (((th) -> tcp_offx2 & 0xf0) >> 4) //상위 4bit만 사용, 하위 4bit은 사용 x
	u_char tcp_flags;
	u_short tcp_win; //windows
	u_short tcp_sum; //checksum
	u_short tcp_urp; //urget ptr
};

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
	//step 4. Ethernet Header 읽기
	struct ethheader* eth = (struct ethheader*)packet; //ethheader struct 모양으로 casting
	if (ntohs(eth->ether_type) != 0x0800) { // BigEndian -> LittleEndian -> Packet IP 확인
		return;
	}

	printf("Ethernet Header\n");
	printf(" Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", //source mac
		eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
		eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf(" Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", //destination mac
		eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
		eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	
	//step 5. IP Header 읽기
	struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader)); //sizeof(struct ethheadr) = 14
	int ip_header_len = ip->iph_ihl * 4;//4byte 단위로 몇 개냐 -> n * 4 = 총 바이트 수
	printf("IP Header (len = %d bytes)\n", ip_header_len);
	printf("From : %s\n", inet_ntoa(ip->iph_sourceip)); //inet_ntoa -> 32bit int를 dot 표기법으로
	printf("To : %s\n", inet_ntoa(ip->iph_destip));

	//step 6. TCP만 처리
	if (ip->iph_protocol != IPPROTO_TCP) {
		printf("Protocol : NOT TCP");
		return;
	}
	printf("Protocol : TCP\n");

	//step 7. TCP header 읽기
	struct tcpheader* tcp = (struct tcpheader*)((u_char*)ip + ip_header_len); //ip_header 다음부터 tcp_header 시작

	int tcp_header_len = TH_OFF(tcp) * 4;
	printf("TCP Header (len = %d bytes)\n", tcp_header_len);
	printf("Src Port : %d\n", ntohs(tcp->tcp_sport));
	printf("Dst Port : %d\n", ntohs(tcp->tcp_dport));
	
	//step 8. HTTP msg 읽기
	//[MAC][IP][TCP][DATA] <- DATA 읽기
	int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
	int payload_len = header->caplen - total_header_len;

	if (payload_len > 0) {
		const u_char* payload = packet + total_header_len;
		printf("HTTP Message (%d bytes\n", payload_len);
		printf("======================================");
		for (int i = 0; i < payload_len; i++) {
			putchar(isprint(payload[i]) ? payload[i] : '.');
		}
		printf("======================================");
	}
	else {
		printf("HTTP Message : None (payload_len = %d)\n", payload_len);
	}
}

int main() {
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	// step 1. NIC 열기
	handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) { //open 실패
		fprintf(stderr, "Couldn't open device : %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	// step 2. 패킷 필터링
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 net = 0;

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		pcap_perror(handle, "Error");
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(handle, &fp) != 0) {
		pcap_perror(handle, "Error");
		exit(EXIT_FAILURE);
	}

	// step 3. packet 캡처
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return 0;
}