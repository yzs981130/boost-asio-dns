# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/yzs/Downloads/clion-2017.3/bin/cmake/bin/cmake

# The command to remove a file.
RM = /home/yzs/Downloads/clion-2017.3/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yzs/CLionProjects/boost-asio-dns

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yzs/CLionProjects/boost-asio-dns/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/boost_asio_dns.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/boost_asio_dns.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/boost_asio_dns.dir/flags.make

CMakeFiles/boost_asio_dns.dir/dns.cpp.o: CMakeFiles/boost_asio_dns.dir/flags.make
CMakeFiles/boost_asio_dns.dir/dns.cpp.o: ../dns.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yzs/CLionProjects/boost-asio-dns/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/boost_asio_dns.dir/dns.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/boost_asio_dns.dir/dns.cpp.o -c /home/yzs/CLionProjects/boost-asio-dns/dns.cpp

CMakeFiles/boost_asio_dns.dir/dns.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/boost_asio_dns.dir/dns.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yzs/CLionProjects/boost-asio-dns/dns.cpp > CMakeFiles/boost_asio_dns.dir/dns.cpp.i

CMakeFiles/boost_asio_dns.dir/dns.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/boost_asio_dns.dir/dns.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yzs/CLionProjects/boost-asio-dns/dns.cpp -o CMakeFiles/boost_asio_dns.dir/dns.cpp.s

CMakeFiles/boost_asio_dns.dir/dns.cpp.o.requires:

.PHONY : CMakeFiles/boost_asio_dns.dir/dns.cpp.o.requires

CMakeFiles/boost_asio_dns.dir/dns.cpp.o.provides: CMakeFiles/boost_asio_dns.dir/dns.cpp.o.requires
	$(MAKE) -f CMakeFiles/boost_asio_dns.dir/build.make CMakeFiles/boost_asio_dns.dir/dns.cpp.o.provides.build
.PHONY : CMakeFiles/boost_asio_dns.dir/dns.cpp.o.provides

CMakeFiles/boost_asio_dns.dir/dns.cpp.o.provides.build: CMakeFiles/boost_asio_dns.dir/dns.cpp.o


# Object files for target boost_asio_dns
boost_asio_dns_OBJECTS = \
"CMakeFiles/boost_asio_dns.dir/dns.cpp.o"

# External object files for target boost_asio_dns
boost_asio_dns_EXTERNAL_OBJECTS =

boost_asio_dns: CMakeFiles/boost_asio_dns.dir/dns.cpp.o
boost_asio_dns: CMakeFiles/boost_asio_dns.dir/build.make
boost_asio_dns: /usr/local/lib/libboost_system.so
boost_asio_dns: /usr/local/lib/libboost_thread.so
boost_asio_dns: /usr/local/lib/libboost_regex.so
boost_asio_dns: CMakeFiles/boost_asio_dns.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yzs/CLionProjects/boost-asio-dns/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable boost_asio_dns"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/boost_asio_dns.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/boost_asio_dns.dir/build: boost_asio_dns

.PHONY : CMakeFiles/boost_asio_dns.dir/build

CMakeFiles/boost_asio_dns.dir/requires: CMakeFiles/boost_asio_dns.dir/dns.cpp.o.requires

.PHONY : CMakeFiles/boost_asio_dns.dir/requires

CMakeFiles/boost_asio_dns.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/boost_asio_dns.dir/cmake_clean.cmake
.PHONY : CMakeFiles/boost_asio_dns.dir/clean

CMakeFiles/boost_asio_dns.dir/depend:
	cd /home/yzs/CLionProjects/boost-asio-dns/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yzs/CLionProjects/boost-asio-dns /home/yzs/CLionProjects/boost-asio-dns /home/yzs/CLionProjects/boost-asio-dns/cmake-build-debug /home/yzs/CLionProjects/boost-asio-dns/cmake-build-debug /home/yzs/CLionProjects/boost-asio-dns/cmake-build-debug/CMakeFiles/boost_asio_dns.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/boost_asio_dns.dir/depend

