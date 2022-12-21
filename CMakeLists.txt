cmake_minimum_required(VERSION 3.5)
project(SecureID LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/)

find_package(mcl REQUIRED)
include_directories(${mcl_INCLUDE_DIRS})

enable_testing()
include(googletest)
add_executable(SecureID_test secure_id_test.cpp secure_id.hpp)
add_dependencies(SecureID_test googletest)
target_link_libraries(SecureID_test ${mcl_LIBRARIES} ${mclbn256_LIBRARIES} ${googletest_STATIC_LIBRARIES})
target_include_directories(SecureID_test PUBLIC ${googletest_INCLUDE_DIRS})
add_test(UnitTest SecureID_test)
