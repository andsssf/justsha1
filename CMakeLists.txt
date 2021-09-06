cmake_minimum_required(VERSION 3.0.0)
project(JUSTSHA1 VERSION 0.1.0)

enable_testing()

include_directories(src/include)

add_subdirectory(src)
add_subdirectory(test)
