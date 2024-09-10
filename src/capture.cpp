#include "capture.h"

// 链路层数据包格式
typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
} ETHHEADER;

// IP层数据包格式
typedef struct {
    int header_len:4;
    int version:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
} IPHEADER;

// 协议映射表
char *Proto[]={
    "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};

static std::string convertIPToString(const unsigned char* destIP) {
    std::ostringstream oss;
    oss << static_cast<unsigned int>(destIP[0]) << '.'
        << static_cast<unsigned int>(destIP[1]) << '.'
        << static_cast<unsigned int>(destIP[2]) << '.'
        << static_cast<unsigned int>(destIP[3]);
    return oss.str();
}

std::unordered_map<std::string, int> Capture::sourMap;
std::priority_queue<std::pair<std::string, int>, std::vector<std::pair<std::string, int>> ,Compare> Capture::heap;

Capture* Capture::instance=nullptr;
std::mutex Capture::i_mutex;//类外初始化

// 回调函数
void Capture::pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    ETHHEADER *eth_header=(ETHHEADER*)pkt_data;
    printf("---------------Begin Analysis-----------------\n");
    printf("----------------------------------------------\n");
    printf("Packet length: %d \n",header->len);
    // 解析数据包IP头部
    if(header->len>=14){
        IPHEADER *ip_header=(IPHEADER*)(pkt_data+14);
        packet_count++;
        // 解析协议类型
        char strType[100];
        if(ip_header->proto>7)
            strcpy(strType,"IP/UNKNWN");
        else
            strcpy(strType,Proto[ip_header->proto]);
        // printf("Source MAC : %02X-%02X-%02X-%02X-%02X-%02X==>",eth_header->SrcMac[0],eth_header->SrcMac[1],eth_header->SrcMac[2],eth_header->SrcMac[3],eth_header->SrcMac[4],eth_header->SrcMac[5]);
        // printf("Dest   MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",eth_header->DestMac[0],eth_header->DestMac[1],eth_header->DestMac[2],eth_header->DestMac[3],eth_header->DestMac[4],eth_header->DestMac[5]);
        // printf("Source IP : %d.%d.%d.%d==>",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);
        // printf("Dest   IP : %d.%d.%d.%d\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);
        std::string sourIp = convertIPToString(ip_header->sourceIP);
        std::string destIp = convertIPToString(ip_header->destIP);

        Capture::sourMap[sourIp]++;
        // printf("Protocol : %s\n",strType);

        // 解析 TCP 或 UDP 头部
        if (ip_header->proto == 6) {  // TCP
            TCPHEADER *tcp_header = (TCPHEADER*)((u_char*)ip_header + sizeof(IPHEADER));
            tcp_packet_count++;
            // printf("Source Port : %d\n", ntohs(tcp_header->src_port));
            // printf("Dest Port : %d\n", ntohs(tcp_header->dst_port));
            // printf("Flags : CWR=%d ECE=%d URG=%d ACK=%d PSH=%d RST=%d SYN=%d FIN=%d\n",
            //        tcp_header->CWR, tcp_header->ECE, tcp_header->URG, tcp_header->ACK,
            //        tcp_header->PSH, tcp_header->RST, tcp_header->SYN, tcp_header->FIN);
        } else if (ip_header->proto == 17) {  // UDP
            UDPHEADER *udp_header = (UDPHEADER*)((u_char*)ip_header + sizeof(IPHEADER));
            udp_packet_count++;
            // printf("Source Port : %d\n", ntohs(udp_header->src_port));
            // printf("Dest Port : %d\n", ntohs(udp_header->dst_port));
        }

        // 显示数据帧内容
        // int i; 
        // for(i=0; i<(int)header->len; ++i)  { 
        //     printf(" %02x", pkt_data[i]); 
        //     if( (i + 1) % 16 == 0 )  
        //         printf("\n"); 
        // } 
        // printf("\n\n");
    }
}

void Capture::start_capture(pcap_t* handle) {
    // 开始捕获数据包
    pcap_loop(handle, -1, pcap_handle, nullptr);
}

