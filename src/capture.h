#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <mutex>
#include <unordered_map>
#include <queue>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

// IP层头部结构体格式
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

// TCP层头部结构体格式
typedef struct {
    u_short src_port;
    u_short dst_port;
    u_int seq_num; // 序列号
    u_int ack_num; // 确认号
    u_char data_offset:4;
    u_char reserved:3;
    u_char NS:1; // 标志位
    u_char CWR:1;
    u_char ECE:1;
    u_char URG:1;
    u_char ACK:1;
    u_char PSH:1;
    u_char RST:1;
    u_char SYN:1;
    u_char FIN:1;
    u_short window;
    u_short checksum;
    u_short urgent_ptr;
} TCPOPTIONS, TCPHEADER;

// UDP层头部结构体格式
typedef struct {
    u_short src_port;
    u_short dst_port;
    u_short len;
    u_short checksum;
} UDPOPTIONS, UDPHEADER;

// DNS头部结构体格式
typedef struct {
    u_short id;
    u_short flags;
    u_short qdcount;
    u_short ancount;
    u_short nscount;
    u_short arcount;
} DNSHEADER;

extern int packet_count;  // 定义一个全局变量来计数数据包
extern int tcp_packet_count;  
extern int udp_packet_count;  
extern int dns_packet_count;
extern int commod;

// 自定义比较器
struct Compare {
    bool operator()(const std::pair<std::string, int>& a,
                    const std::pair<std::string, int>& b) const {
        // 按照 "count" 键的值进行排序
        return a.second < b.second; // 使得 a 的 "count" 值小于 b 的 "count" 值时返回 false
    }
};

class Capture{ // 单例模式
public:
    ~Capture(){};

    static Capture* getinstance() {//双重锁模式
		if (instance == nullptr) {//先判断是否为空，如果为空则进入，不为空说明已经存在实例，直接返回
            //进入后加锁
			i_mutex.lock();
			if (instance == nullptr) {//再判断一次，确保不会因为加锁期间多个线程同时进入
				instance = new Capture();
			}
			i_mutex.unlock();//解锁
		}
		return instance;
	}

    void start_capture(pcap_t*);
    static void pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data);
    static std::vector<std::pair<std::string, int>>& getTopKIPs(int k = 5);
    static std::unordered_map<std::string, int> sourMap; // 源地址ip
    static std::priority_queue<std::pair<std::string, int>, std::vector<std::pair<std::string, int>> ,Compare> heap;

private:
    Capture() {};
    Capture(const Capture&) {};
    static Capture* instance;
	static std::mutex i_mutex;//锁

};

#endif