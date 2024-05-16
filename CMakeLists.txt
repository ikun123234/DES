cmake_minimum_required(VERSION 3.21.1)
project(DES C)

set(CMAKE_C_STANDARD 11)

add_executable(DesEncrypt crypt.c ZhiHuanTable.h JinZhiSwitch.h Des.h OpMode.h)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR})
