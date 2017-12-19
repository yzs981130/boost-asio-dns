cmake_minimum_required(VERSION 2.9)
project(boost_asio_dns)

macro(use_cxx11)
    if (CMAKE_VERSION VERSION_LESS "3.1")
        if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            set (CMAKE_CXX_FLAGS "-std=gnu++11 ${CMAKE_CXX_FLAGS}")
        endif ()
    else ()
        set (CMAKE_CXX_STANDARD 11)
    endif ()
endmacro(use_cxx11)

use_cxx11()

SET(Boost_USE_STATIC_LIBS ON)
SET(Boost_USE_MULTITHREAD ON)

find_package(Boost 1.42.0 REQUIRED system thread regex chrono)


SET(USED_LIBS ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_REGEX_LIBRARY} ${Boost_CHRONO_LIBRARY} -pthread)

add_executable(boost_asio_dns dns.cpp dns_packet.h)
target_link_libraries(boost_asio_dns ${USED_LIBS})

