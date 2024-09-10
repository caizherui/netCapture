#include "capture.h"

// 链路层数据包格式
typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
} ETHHEADER;

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
std::mutex all_lock;
std::mutex tcp_lock;
std::mutex udp_lock;
std::mutex dns_lock;

// 回调函数
void Capture::pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    ETHHEADER *eth_header=(ETHHEADER*)pkt_data;
    if (commod == 1) {
        printf("---------------Begin Analysis-----------------\n");
        printf("----------------------------------------------\n");
        printf("Packet length: %d \n",header->len);
    }
    // 解析数据包IP头部
    if(header->len>=14){
        IPHEADER *ip_header=(IPHEADER*)(pkt_data+14);
        std::unique_lock<std::mutex> lck(all_lock);
        packet_count++;
        lck.unlock();
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
            std::unique_lock<std::mutex> lck(tcp_lock);
            tcp_packet_count++;
            lck.unlock();
            if (commod == 1) {
                printf("Source Port : %d\n", ntohs(tcp_header->src_port));
                printf("Dest Port : %d\n", ntohs(tcp_header->dst_port));
                printf("Flags : CWR=%d ECE=%d URG=%d ACK=%d PSH=%d RST=%d SYN=%d FIN=%d\n",
                    tcp_header->CWR, tcp_header->ECE, tcp_header->URG, tcp_header->ACK,
                    tcp_header->PSH, tcp_header->RST, tcp_header->SYN, tcp_header->FIN);
            }
        } else if (ip_header->proto == 17) {  // UDP
            UDPHEADER *udp_header = (UDPHEADER*)((u_char*)ip_header + sizeof(IPHEADER));
            std::unique_lock<std::mutex> lck(udp_lock);
            udp_packet_count++;
            lck.unlock();
            if (commod == 1) {
                printf("Source Port : %d\n", ntohs(udp_header->src_port));
                printf("Dest Port : %d\n", ntohs(udp_header->dst_port));
            }
            // 检查是否为DNS请求 根据端口号进行检查
            if (ntohs(udp_header->src_port) == 53 || ntohs(udp_header->dst_port) == 53) { // 网络字节序转化为主机字节序
                DNSHEADER *dns_header = (DNSHEADER*)((u_char*)udp_header + sizeof(UDPHEADER));
                std::unique_lock<std::mutex> lck(dns_lock);
                dns_packet_count++;
                lck.unlock();

                if (commod == 1) {
                    // 打印DNS头部信息
                    printf("DNS ID: %d\n", ntohs(dns_header->id));
                    printf("DNS Flags: %04x\n", ntohs(dns_header->flags));
                    printf("Query Count: %d\n", ntohs(dns_header->qdcount));
                    printf("Answer Count: %d\n", ntohs(dns_header->ancount));
                    printf("Name Server Count: %d\n", ntohs(dns_header->nscount));
                    printf("Additional Count: %d\n", ntohs(dns_header->arcount));
                }
            }
        }

        // 显示数据帧内容
        if (commod == 1) {
            int i; 
            for(i=0; i<(int)header->len; ++i)  { 
                printf(" %02x", pkt_data[i]); 
                if( (i + 1) % 16 == 0 )  
                    printf("\n"); 
            } 
            printf("\n\n");
        }
    }
}

void Capture::start_capture(pcap_t* handle) {
    // 开始捕获数据包
    pcap_loop(handle, -1, pcap_handle, nullptr);
}

