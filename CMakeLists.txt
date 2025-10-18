# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(HomomorphicEncryption VERSION 1.0 LANGUAGES CXX)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the include directory for header files
include_directories(${PROJECT_SOURCE_DIR}/include)

# Collect all source files from the subdirectories of the src directory
file(GLOB_RECURSE SOURCES ${PROJECT_SOURCE_DIR}/src/*/*.cpp)

# Add the executable
set(TARGET_NAME demo)
add_executable(${TARGET_NAME} ${SOURCES})

# Add SEAL library
set(CMAKE_PREFIX_PATH "~/Documents/C++_workspace/SEAL_lib" CACHE STRING "SEAL library path")
find_package(SEAL 4.1 REQUIRED)
target_link_libraries(${TARGET_NAME} SEAL::seal)

# Specify compile options
#target_compile_options(${TARGET_NAME} PRIVATE -std=c++23 -ggdb)
target_compile_options(${TARGET_NAME} PRIVATE -std=c++23 )
#target_compile_options(${TARGET_NAME} PRIVATE -std=c++23 -ggdb -pedantic-errors -Wall -Weffc++ -Wextra -Wconversion -Wsign-conversion)
