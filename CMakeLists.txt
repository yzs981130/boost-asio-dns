cmake_minimum_required(VERSION 2.9)
project(boost_asio_dns)

set(CMAKE_CXX_STANDARD 17)

SET(Boost_USE_STATIC_LIBS OFF)
SET(Boost_USE_MULTITHREAD ON)

find_package(Boost 1.42.0 REQUIRED system thread regex)


SET(USED_LIBS ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_REGEX_LIBRARY} -pthread)

add_executable(boost_asio_dns dns.cpp dns_packet.h dns-server.cpp dns-server.h common.h)
target_link_libraries(boost_asio_dns ${USED_LIBS})