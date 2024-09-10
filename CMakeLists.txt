cmake_minimum_required(VERSION 3.10)  # 设置所需的 CMake 最低版本

# 项目信息
project(NetCapture VERSION 1.0 LANGUAGES CXX)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加可执行文件
add_executable(${PROJECT_NAME} src/ncurse.cpp)

# 查找 libpcap 库
find_package(PkgConfig REQUIRED)
pkg_check_modules(PC_LIBPCAP libpcap)

find_package(Ncurses REQUIRED)

include_directories(${PC_LIBPCAP_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} ${PC_LIBPCAP_LIBRARIES})
target_link_libraries(${PROJECT_NAME} ${NCURSES_LIBRARIES})

# 添加其他编译选项（可选）
# add_definitions(-DFOO=1)

# 添加其他源文件（可选）
# add_executable(another_target src/utils.cpp)