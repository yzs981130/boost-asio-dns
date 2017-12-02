cmake_minimum_required(VERSION 2.9)
project(boost_asio_dns)

set(CMAKE_CXX_STANDARD 11)

find_package(Boost 1.42.0 REQUIRED system regex)


SET(USED_LIBS ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_REGEX_LIBRARY})

add_executable(boost_asio_dns main.cpp)
target_link_libraries(boost_asio_dns ${USED_LIBS})