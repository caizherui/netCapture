#ifndef DISPLAY_H
#define DISPLAY_H

#include <thread>
#include <mutex>
#include <ncurses.h>
#include <chrono>
#include <iostream>

extern int packet_count;
extern int tcp_packet_count;  
extern int udp_packet_count;  
extern int dns_packet_count;
extern int commod;

class Display {
public:
    ~Display(){};

    static Display* getinstance() {//双重锁模式
		if (instance == nullptr) {//先判断是否为空，如果为空则进入，不为空说明已经存在实例，直接返回
            //进入后加锁
			i_mutex.lock();
			if (instance == nullptr) {//再判断一次，确保不会因为加锁期间多个线程同时进入
				instance = new Display();
			}
			i_mutex.unlock();//解锁
		}
		return instance;
	}

    void update_display();

private:
    Display() {};
    Display(const Display&) {};
    static Display* instance;
	static std::mutex i_mutex;//锁
};

#endif // DISPLAY_H