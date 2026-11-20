# Engine tests: tracer.cpp on its own — no Qt, no window, and nothing is sent
# off the machine. Configure with -DOPENMTR_BUILD_TESTS=ON, then
#
#   cmake --build build --target engine_tests
#   ctest --test-dir build --output-on-failure
#
# They need no Qt, so -DOPENMTR_BUILD_GUI=OFF builds them without it. CI runs
# them on macOS and on Linux (glibc and musl, see the core-linux job), never
# yet on Windows.
find_package(Threads REQUIRED)

add_executable(engine_tests engine_tests.cpp ${PROJECT_SOURCE_DIR}/src/tracer.cpp)
# Nothing here is a Qt class (the GUI section turns AUTOMOC on after this).
set_target_properties(engine_tests PROPERTIES AUTOMOC OFF)
target_include_directories(engine_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(engine_tests PRIVATE Threads::Threads)
if(NOT MSVC)
    target_compile_options(engine_tests PRIVATE -Wall -Wextra)
endif()

foreach(name IN ITEMS dns_lifetime status_text utf8_names v6_silent_first_hop
                      stop_before_start stop_right_after_start refused_socket
                      raw_socket raw_fallback)
    add_test(NAME engine.${name} COMMAND engine_tests ${name})
    # A regression here can hang rather than crash, so bound every case.
    # 77 = this machine cannot run the case (e.g. no IPv6 ICMP socket):
    # reported as skipped, never as passed.
    set_tests_properties(engine.${name} PROPERTIES TIMEOUT 20 SKIP_RETURN_CODE 77)
endforeach()

# Cases that open no ICMP socket.
foreach(name IN ITEMS icmp_checksum name_control_chars no_thread_for_dns)
    add_test(NAME engine.${name} COMMAND engine_tests ${name})
    set_tests_properties(engine.${name} PROPERTIES TIMEOUT 20 SKIP_RETURN_CODE 77)
endforeach()

# Report format golden files (tests/golden/): report_core's builders, byte
# for byte. report_core still uses QtCore, so this is built only where a Qt
# is found (it needs no display); the Qt-free Linux CI job skips it.
find_package(Qt6 QUIET COMPONENTS Core)
if(TARGET Qt6::Core)
    add_executable(report_golden_tests report_golden_tests.cpp
                   ${PROJECT_SOURCE_DIR}/src/report_core.cpp
                   ${PROJECT_SOURCE_DIR}/src/tracer.cpp)
    set_target_properties(report_golden_tests PROPERTIES AUTOMOC OFF)
    target_include_directories(report_golden_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(report_golden_tests PRIVATE Qt6::Core Threads::Threads)
    if(NOT MSVC)
        target_compile_options(report_golden_tests PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME report.golden
             COMMAND report_golden_tests check ${CMAKE_CURRENT_SOURCE_DIR}/golden)
    set_tests_properties(report.golden PROPERTIES TIMEOUT 20)
endif()

# ICMP receive-path parsers (src/icmp_parse.h) against hand-made packets.
add_executable(icmp_parse_tests icmp_parse_tests.cpp)
set_target_properties(icmp_parse_tests PROPERTIES AUTOMOC OFF)
target_include_directories(icmp_parse_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)
if(NOT MSVC)
    target_compile_options(icmp_parse_tests PRIVATE -Wall -Wextra)
endif()
add_test(NAME icmp_parse COMMAND icmp_parse_tests)
set_tests_properties(icmp_parse PROPERTIES TIMEOUT 60)

# libFuzzer target for the same parsers (clang only; see tests/fuzz/).
option(OPENMTR_BUILD_FUZZERS "Build the libFuzzer targets in tests/fuzz/ (clang)" OFF)
if(OPENMTR_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "OPENMTR_BUILD_FUZZERS needs clang (libFuzzer)")
    endif()
    add_executable(fuzz_icmp fuzz/fuzz_icmp.cpp)
    set_target_properties(fuzz_icmp PROPERTIES AUTOMOC OFF)
    target_include_directories(fuzz_icmp PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_compile_options(fuzz_icmp PRIVATE -g -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_icmp PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

# ASN lookups (src/asn_resolver.cpp, src/asncache.cpp) without a network:
# query names, TXT parsing, unroutable addresses, hand-made DNS answers, and
# the cache's pending timeout with a stand-in lookup.
add_executable(asn_parse_tests asn_parse_tests.cpp ${PROJECT_SOURCE_DIR}/src/asn_resolver.cpp
               ${PROJECT_SOURCE_DIR}/src/asncache.cpp)
set_target_properties(asn_parse_tests PROPERTIES AUTOMOC OFF)
target_include_directories(asn_parse_tests PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(asn_parse_tests PRIVATE ${OPENMTR_RESOLV_LIBS} Threads::Threads)
if(WIN32)
    target_link_libraries(asn_parse_tests PRIVATE ws2_32 dnsapi)
endif()
if(NOT MSVC)
    target_compile_options(asn_parse_tests PRIVATE -Wall -Wextra)
endif()
add_test(NAME asn_parse COMMAND asn_parse_tests)
set_tests_properties(asn_parse PROPERTIES TIMEOUT 20)
