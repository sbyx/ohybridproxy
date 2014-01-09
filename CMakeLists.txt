cmake_minimum_required(VERSION 2.8)
project(ohybridproxy C)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")

add_definitions(-D_GNU_SOURCE -Wall -Wextra)

if(${L_LEVEL})
	add_definitions(-DL_LEVEL=${L_LEVEL})
endif(${L_LEVEL})

add_executable(ohybridproxy src/ohybridproxy.c src/dns2mdns.c)
target_link_libraries(ohybridproxy ubox)

# Unit test stuff

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")

# With this, 'make check' works even in a clean tree (sigh, cmake..)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
enable_testing()
include_directories(src)

#add_executable(test_dummy test/test_dummy.c)
#add_test(dummy test_dummy)
#add_dependencies(check test_dummy)

add_executable(test_dnsutil test/test_dnsutil.c)
add_test(dnsutil test_dnsutil)
add_dependencies(check test_dnsutil)

add_executable(test_dns2mdns test/test_dns2mdns.c)
add_test(dns2mdns test_dns2mdns)
add_dependencies(check test_dns2mdns)

add_executable(test_mdnsresponder test/test_mdnsresponder.c)
target_link_libraries(test_mdnsresponder ubox)

add_executable(test_client test/test_client.c)
target_link_libraries(test_client ubox)

# Installation rules
install(TARGETS ohybridproxy DESTINATION sbin/)

# Packaging rules
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Steven Barth <steven@midlink.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ohybridproxy")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)

SET(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")

include(CPack)
