cmake_minimum_required(VERSION 3.16)
project(memwars)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")

add_executable(memwars main.cpp)