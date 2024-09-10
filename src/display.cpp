#include "display.h"  // 包含头文件
#include "capture.h"

Display* Display::instance=nullptr;
std::mutex Display::i_mutex;//类外初始化

void Display::update_display() {
    // 初始化ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    setlocale(LC_ALL, "");  // 设置本地化环境

    // 初始化颜色对
    start_color();
    init_pair(1, COLOR_RED, COLOR_BLACK);  // 设置红色文本和黑色背

    // 创建一个子窗口来显示数据包信息
    WINDOW *win = newwin(50, 80, 5, 10);
    box(win, 0, 0);
    wrefresh(win);

    while (true) {
        // 更新ncurses窗口
        wclear(win);

        mvwprintw(win, 20, 10, "High frequency IP:");

        int i = 20;

        // for (auto &it:Capture::sourMap) {
        //     mvwprintw(win, ++i, 10, "Source IP:%s    Num:%d", it.first.c_str(), it.second);
        // }

        for (auto &it:Capture::sourMap) {
            Capture::heap.push({it.first, it.second});
        }

        int count = 0;

        // 设置颜色属性
        wattron(win, COLOR_PAIR(1));  // 启用颜色对 1

        // 选出top5高频访问的ip地址
        while (!Capture::heap.empty() && count < 5) {
            auto it = Capture::heap.top();
            mvwprintw(win, ++i, 10, "Source IP:%s    Num:%d", it.first.c_str(), it.second);
            Capture::heap.pop();
            count++;
        }

        // 取消颜色属性
        wattroff(win, COLOR_PAIR(1));


        mvwprintw(win, 1, 1, "Network traffic monitoring terminal");
        mvwprintw(win, 10, 1, "Total packets captured: %d", packet_count);

        wrefresh(win);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));  // 每秒更新两次

    }

    // 清理ncurses环境
    delwin(win);
    endwin();
}