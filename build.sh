#!/bin/bash

# 检查是否在项目根目录
if [ ! -f "CMakeLists.txt" ]; then
  echo "请从netCapture(根目录开始执行此程序)"
  exit 1
fi

# 创建并进入构建目录，若已存在build目录，将其删去
BUILD_DIR="build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# 配置 CMake
cmake ..
if [ $? -ne 0 ]; then
  echo "CMake 配置失败"
  exit 1
fi

# 构建项目
make
if [ $? -ne 0 ]; then
  echo "构建失败"
  exit 1
fi

# 执行测试（如果有的话）
if [ -d "tests" ]; then
  cd tests
  ctest
  if [ $? -ne 0 ]; then
    echo "测试失败"
    exit 1
  fi
  cd ..
fi

echo "构建成功！"