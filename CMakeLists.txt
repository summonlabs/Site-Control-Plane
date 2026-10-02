cmake_minimum_required(VERSION 3.21)

project(SiteControlPlane
        VERSION 1.0.0
        DESCRIPTION "Deterministic site-level control plane for one physical data center site (DCCP)"
        HOMEPAGE_URL "https://github.com/summonlabs/Site-Control-Plane"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(SCP_BUILD_TESTS "Build the Site Control Plane test suite" ON)
option(SCP_BUILD_TOOLS "Build the scpctl inspection and planning CLI" ON)
option(SCP_BUILD_EXAMPLES "Build the Site Control Plane examples" ON)
option(SCP_BUILD_BENCHMARKS "Build the Site Control Plane benchmarks" ON)
option(SCP_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(SCP_ENABLE_ASAN "Build with AddressSanitizer where the toolchain supports it" OFF)
option(SCP_ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer where supported" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# The library uses std::mutex and std::thread-free synchronisation primitives, so
# on platforms where those live in a separate link library the requirement has to
# travel with the exported target. It is expressed PUBLIC for exactly that
# reason, and the package config re-finds it for consumers.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Warning configuration: strict, and never suppressed with pragmas
# ---------------------------------------------------------------------------
add_library(scp_warnings INTERFACE)
if(MSVC)
  target_compile_options(scp_warnings INTERFACE /W4 /permissive- /Zc:__cplusplus /Zc:preprocessor /utf-8)
  if(SCP_WARNINGS_AS_ERRORS)
    target_compile_options(scp_warnings INTERFACE /WX)
  endif()
  target_compile_definitions(scp_warnings INTERFACE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(scp_warnings INTERFACE
                         -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
                         -Wold-style-cast -Wcast-qual -Wdouble-promotion -Wformat=2
                         -Wundef -Wnull-dereference -Wnon-virtual-dtor -Woverloaded-virtual
                         -Wcast-align -Wunused -Wredundant-decls)
  if(SCP_WARNINGS_AS_ERRORS)
    target_compile_options(scp_warnings INTERFACE -Werror)
  endif()
endif()

set(SCP_SANITIZER_FLAGS "")
if(SCP_ENABLE_ASAN)
  if(MSVC)
    list(APPEND SCP_SANITIZER_FLAGS /fsanitize=address)
  else()
    list(APPEND SCP_SANITIZER_FLAGS -fsanitize=address -fno-omit-frame-pointer)
  endif()
endif()
if(SCP_ENABLE_UBSAN)
  if(MSVC)
    message(WARNING "SCP_ENABLE_UBSAN is not supported by MSVC; ignoring")
  else()
    list(APPEND SCP_SANITIZER_FLAGS -fsanitize=undefined -fno-omit-frame-pointer)
  endif()
endif()
if(SCP_SANITIZER_FLAGS)
  target_compile_options(scp_warnings INTERFACE ${SCP_SANITIZER_FLAGS})
  target_link_options(scp_warnings INTERFACE ${SCP_SANITIZER_FLAGS})
endif()

# ---------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------
add_library(site_control_plane
  src/authority.cpp
  src/canonical.cpp
  src/checked.cpp
  src/composition.cpp
  src/digest.cpp
  src/evidence.cpp
  src/explain.cpp
  src/ids.cpp
  src/journal.cpp
  src/journal_format.cpp
  src/journal_lock.cpp
  src/platform.cpp
  src/plan.cpp
  src/policy.cpp
  src/readiness.cpp
  src/runtime.cpp
  src/site_state.cpp
  src/status.cpp
  src/text.cpp
  src/time.cpp
  src/version.cpp
)
add_library(SiteControlPlane::site_control_plane ALIAS site_control_plane)

target_include_directories(site_control_plane
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

# The warnings interface is a build-time concern only; it must not leak into the
# exported package as a usage requirement for consumers.
target_link_libraries(site_control_plane PRIVATE "$<BUILD_INTERFACE:scp_warnings>")
target_link_libraries(site_control_plane PUBLIC Threads::Threads)
target_compile_features(site_control_plane PUBLIC cxx_std_20)
set_target_properties(site_control_plane PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  OUTPUT_NAME site_control_plane)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if(SCP_BUILD_TOOLS)
  add_executable(scpctl tools/scpctl/main.cpp)
  target_link_libraries(scpctl PRIVATE site_control_plane scp_warnings)
  set_target_properties(scpctl PROPERTIES OUTPUT_NAME scpctl)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
if(SCP_BUILD_EXAMPLES)
  add_executable(scp_example_site_turnup examples/site_turnup.cpp)
  target_link_libraries(scp_example_site_turnup PRIVATE site_control_plane scp_warnings)

  add_executable(scp_example_evidence_publisher examples/evidence_publisher.cpp)
  target_link_libraries(scp_example_evidence_publisher PRIVATE site_control_plane scp_warnings)

endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------
if(SCP_BUILD_BENCHMARKS)
  add_executable(scp_bench bench/scp_bench.cpp)
  target_link_libraries(scp_bench PRIVATE site_control_plane scp_warnings)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(SCP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Installation and package export
# ---------------------------------------------------------------------------
install(TARGETS site_control_plane
        EXPORT SiteControlPlaneTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/scp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(SCP_BUILD_TOOLS)
  install(TARGETS scpctl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(EXPORT SiteControlPlaneTargets
        FILE SiteControlPlaneTargets.cmake
        NAMESPACE SiteControlPlane::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SiteControlPlane)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SiteControlPlaneConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/SiteControlPlaneConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SiteControlPlane)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/SiteControlPlaneConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
  ARCH_INDEPENDENT)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/SiteControlPlaneConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/SiteControlPlaneConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SiteControlPlane)

install(FILES README.md LICENSE NOTICE
        DESTINATION ${CMAKE_INSTALL_DATADIR}/SiteControlPlane
        OPTIONAL)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
message(STATUS "Site Control Plane ${PROJECT_VERSION}")
message(STATUS "  build type           : ${CMAKE_BUILD_TYPE}")
message(STATUS "  compiler             : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  warnings as errors   : ${SCP_WARNINGS_AS_ERRORS}")
message(STATUS "  sanitizer flags      : ${SCP_SANITIZER_FLAGS}")
message(STATUS "  tests/tools/examples : ${SCP_BUILD_TESTS}/${SCP_BUILD_TOOLS}/${SCP_BUILD_EXAMPLES}")
