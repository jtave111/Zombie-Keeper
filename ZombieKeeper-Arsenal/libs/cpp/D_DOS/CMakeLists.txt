cmake_minimum_required(VERSION 3.20)
project(D_DOS)

add_library(D_DOS STATIC
    DOS.cpp
        h/DOS.h
)

target_include_directories(D_DOS
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/h
    
)

target_compile_features(D_DOS PUBLIC cxx_std_17)

target_compile_options(D_DOS PRIVATE
    -Wall -Wextra -Wpedantic
)


