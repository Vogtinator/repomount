cmake_minimum_required(VERSION 3.6)
include(FeatureSummary)

project(repomount VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3 IMPORTED_TARGET)
pkg_check_modules(RPM REQUIRED rpm IMPORTED_TARGET)

set(REPOMOUNT_SOURCES
        repovfs.h repovfs.cpp
        main.cpp)

add_executable(repomount ${REPOMOUNT_SOURCES})
target_compile_definitions(repomount PRIVATE FUSE_USE_VERSION=31)
target_link_libraries(repomount PRIVATE PkgConfig::FUSE3 PkgConfig::RPM)

install(TARGETS repomount
    LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR})

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
