#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include "capture.h"
#include "display.h"

int packet_count = 0; // 总的流量包
int tcp_packet_count = 0; // tcp协议的流量包总量
int udp_packet_count = 0; // udp协议的流量包总量

int main(int argc, char **argv) {
    pcap_if_t* alldevs; // 存储所有设备的链表
    char errbuf[PCAP_ERRBUF_SIZE]; // 用于存放错误信息的缓冲区

    // 获取所有可用的网络设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    std::vector<pcap_if_t*> selected_devs; // 存储抓包的目标设备
    // 打印所有网络设备
    for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
        if (!dev->description) { // 筛选出没有描述的设备
            std::cout << "Device: " << dev->name << std::endl;
            selected_devs.push_back(dev);
        }
    }
    Display* display = Display::getinstance();

    // 创建更新显示的线程
    std::thread display_thread(&Display::update_display, display);

    // 打开并抓取每个符合条件的设备，多线程抓取
    for (auto* dev : selected_devs) {
        std::string device = dev->name;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *phandle;
        bpf_u_int32 ipaddress, ipmask;
        struct bpf_program fcode;
        int datalink;

        // 查找可用的网络设备
        if ((device = pcap_lookupdev(errbuf)) == "") {
            std::cerr << "Error: " << errbuf << std::endl;
            return 1;
        }
        else
            std::cout << "Device: " << device << std::endl;

        // 打开网络设备
        phandle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (phandle == nullptr) {
            std::cerr << "Error: " << errbuf << std::endl;
            return 1;
        }

        // 查找网络设备的IP地址和掩码
        if (pcap_lookupnet(device.c_str(), &ipaddress, &ipmask, errbuf) == -1) {
            std::cerr << "Error: " << errbuf << std::endl;
            return 1;
        }
        else {
            char ip[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &ipaddress, ip, sizeof(ip)) == nullptr)
                std::cerr << "Error: inet_ntop error" << std::endl;
            else if (inet_ntop(AF_INET, &ipmask, mask, sizeof(mask)) == nullptr)
                std::cerr << "Error: inet_ntop error" << std::endl;
            std::cout << "IP address: " << ip << ", Network Mask: " << mask << std::endl;
        }

        int flag = 1;
        while (flag) {
            // 输入过滤器
            std::cout << "Input packet Filter: ";
            std::string filterString;
            std::cin >> filterString;
            if (pcap_compile(phandle, &fcode, filterString.c_str(), 0, ipmask) == -1)
                std::cerr << "Error: " << pcap_geterr(phandle) << ", please input again...." << std::endl;
            else
                flag = 0;
        }

        // 设置过滤器
        if (pcap_setfilter(phandle, &fcode) == -1) {
            std::cerr << "Error: " << pcap_geterr(phandle) << std::endl;
            return 1;
        }

        // 获取数据链路类型
        if ((datalink = pcap_datalink(phandle)) == -1) {
            std::cerr << "Error: " << pcap_geterr(phandle) << std::endl;
            return 1;
        }
        std::cout << "Data link type: " << datalink << std::endl;

        Capture* capture = Capture::getinstance();

        // 创建捕获数据包的线程
        std::thread capture_thread(&Capture::start_capture, capture, phandle);
        capture_thread.detach(); // 脱离主线程
    }

    display_thread.join();

    // 清理
    pcap_freealldevs(alldevs);

    return 0;
}