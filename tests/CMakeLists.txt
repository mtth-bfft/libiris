cmake_minimum_required(VERSION 3.8.2)


# Remove trailing '\' and '/' at the end of the path, so can reliably compare
STRING(REGEX REPLACE "[/\\]+$" "" CMAKE_SOURCE_DIR ${CMAKE_SOURCE_DIR})
STRING(REGEX REPLACE "[/\\]+$" "" CMAKE_CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
    set(BUILD_SHARED_LIBS TRUE)
endif()

set(MODULE_FILES src/libdummy.c)

add_library(libdummy SHARED ${MODULE_FILES})

target_include_directories(libdummy PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS libdummy DESTINATION .)
