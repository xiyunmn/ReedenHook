cmake_minimum_required(VERSION 3.22.1)
project(reeden_unlock)

add_library(reeden_unlock SHARED
    reeden_unlock_v2.cpp
)

find_library(log-lib log)

target_compile_features(reeden_unlock PRIVATE cxx_std_20)
target_compile_options(reeden_unlock PRIVATE
    -Wall
    -Wextra
    -fno-exceptions
    -fno-rtti
    -O2
)

target_link_libraries(reeden_unlock
    ${log-lib}
)
