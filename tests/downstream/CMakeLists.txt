cmake_minimum_required(VERSION 3.21)

project(SiteControlPlaneDownstream LANGUAGES CXX)

# This consumer is configured from outside the Site Control Plane source tree and
# linked only against the installed package. Nothing here knows the build tree
# exists, which is what makes it evidence of distributability rather than of an
# in-tree build.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SiteControlPlane 1.0 REQUIRED CONFIG)

add_executable(downstream_consumer main.cpp)
target_link_libraries(downstream_consumer PRIVATE SiteControlPlane::site_control_plane)

# The consumer must not need to know the transitive link requirements of the
# library: if it did, the exported target would be incomplete and this build
# would fail on the platform that needs them.
if(MSVC)
  target_compile_options(downstream_consumer PRIVATE /W4)
else()
  target_compile_options(downstream_consumer PRIVATE -Wall -Wextra -Wpedantic)
endif()
