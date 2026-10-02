# Site Control Plane test suite.
#
# Every test is a standalone executable that returns non-zero on failure. No test
# carries a timeout: a hanging test is a defect to diagnose, not to kill.

add_library(scp_test_support STATIC
  support/test_support.cpp
  support/journal_probe.cpp
)
target_include_directories(scp_test_support PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/support"
  "${CMAKE_SOURCE_DIR}/src"
)
target_link_libraries(scp_test_support PUBLIC site_control_plane)
# PUBLIC, and build-interface only: the sanitizer flags and warning flags carried
# by scp_warnings have to reach the test executables themselves, because an
# instrumented object file must be linked by an instrumented link line. Keeping
# it inside $<BUILD_INTERFACE:...> means none of it can reach the installed
# package.
target_link_libraries(scp_test_support PUBLIC "$<BUILD_INTERFACE:scp_warnings>")

function(scp_add_test name)
  add_executable(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE scp_test_support)
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

scp_add_test(test_status)
scp_add_test(test_evidence)
scp_add_test(test_authority)
scp_add_test(test_readiness)
scp_add_test(test_plan)
scp_add_test(test_composition_determinism)
scp_add_test(test_staleness_and_conflict)
scp_add_test(test_property_composition)
scp_add_test(test_journal)
scp_add_test(test_recovery)
scp_add_test(test_multiprocess)
scp_add_test(test_concurrency)

if(SCP_BUILD_TOOLS)
  scp_add_test(test_cli)
  target_compile_definitions(test_cli PRIVATE SCP_TOOL_PATH="$<TARGET_FILE:scpctl>")
  add_dependencies(test_cli scpctl)
endif()

# The downstream consumer is configured, built and run against a fresh install of
# this build tree, from outside the source tree. It is the distributability
# proof: an in-tree build is not evidence that the package works.
add_test(NAME downstream_consumer
         COMMAND ${CMAKE_COMMAND}
                 -DSCP_SOURCE_DIR=${CMAKE_SOURCE_DIR}
                 -DSCP_BINARY_DIR=${CMAKE_BINARY_DIR}
                 -DSCP_CONSUMER_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/downstream
                 -DSCP_WORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/downstream-work
                 -DSCP_GENERATOR=${CMAKE_GENERATOR}
                 -DSCP_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                 -DSCP_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/downstream/run_consumer.cmake)
set_tests_properties(downstream_consumer PROPERTIES
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
