cmake_minimum_required (VERSION 3.4)

if (${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows")
    set(CMAKE_CXX_COMPILER "icx-cl")
    set(CMAKE_CXX_FLAGS "fsycl")

else()
    set(CMAKE_CXX_COMPILER "icpx")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsycl")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lpcap")
endif()

project (TBB-TASK-SYCL LANGUAGES CXX)
add_subdirectory (src)
