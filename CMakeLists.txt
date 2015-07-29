cmake_minimum_required(VERSION 2.8)

project(libdetectproxy)

set (HEADERS detectproxy/detectproxy.hpp)
set (SRCS detectproxy/detectproxy.cpp)

# Build both shared and static libs

add_library(detectproxy SHARED ${SRCS} ${HEADERS})
set_target_properties (detectproxy PROPERTIES DEBUG_POSTFIX "-d")
set_target_properties(detectproxy PROPERTIES COMPILE_DEFINITIONS LIBDETECTPROXY_DYN_LINK)


add_library(detectproxy-static ${SRCS} ${HEADERS})
set_target_properties(detectproxy-static PROPERTIES DEBUG_POSTFIX "-d")
set_target_properties(detectproxy-static PROPERTIES OUTPUT_NAME "detectproxy")
if(MSVC)
   set_target_properties(detectproxy-static PROPERTIES PREFIX "lib")
endif()

install(TARGETS detectproxy detectproxy-static
   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
   )

install(FILES ${HEADERS}
   DESTINATION include/detectproxy
   )

include_directories(.)
add_executable(test_1 test/test_1.cpp)
target_link_libraries(test_1 detectproxy-static)

add_executable(test_2 test/test_2.cpp)
