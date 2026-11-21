# ============================================================================
#  cmake/OpenMTRCore.cmake — the Qt-free core, compiled into each front end
#
#  The engine, the report builders, the ASN lookups and the report-mode
#  command line: everything both the window app and a build without Qt run.
#  openmtr_add_core(<target>) compiles these sources straight into <target>,
#  so that target's own compile and link options (the app's /W4 /WX,
#  /guard:cf, LTO, debug-info split) apply to them unchanged, and links
#  what they need.
# ============================================================================

set(OPENMTR_CORE_SOURCES
    ${PROJECT_SOURCE_DIR}/src/tracer.cpp        ${PROJECT_SOURCE_DIR}/src/tracer.h
    ${PROJECT_SOURCE_DIR}/src/icmp_parse.h
    ${PROJECT_SOURCE_DIR}/src/report_core.cpp   ${PROJECT_SOURCE_DIR}/src/report_core.h
    ${PROJECT_SOURCE_DIR}/src/textutil.cpp      ${PROJECT_SOURCE_DIR}/src/textutil.h
    ${PROJECT_SOURCE_DIR}/src/asncache.cpp      ${PROJECT_SOURCE_DIR}/src/asncache.h
    ${PROJECT_SOURCE_DIR}/src/asn_resolver.cpp  ${PROJECT_SOURCE_DIR}/src/asn_resolver.h
    ${PROJECT_SOURCE_DIR}/src/versioninfo.cpp   ${PROJECT_SOURCE_DIR}/src/versioninfo.h
    ${PROJECT_SOURCE_DIR}/src/cli.cpp           ${PROJECT_SOURCE_DIR}/src/cli.h
)

find_package(Threads REQUIRED)

# ---- System resolver (ASN lookups, src/asn_resolver.cpp) ---------------------
# res_query() and ns_initparse()/ns_parserr() are in the C library itself on
# musl (OpenWrt), but in libresolv on glibc and macOS (where the ns_* names
# are macros for libresolv's res_9_* symbols, hence a link test rather than
# a symbol check). Windows uses DnsQuery_W (dnsapi) instead.
set(OPENMTR_RESOLV_LIBS "")
if(NOT WIN32)
    include(CheckCXXSourceCompiles)
    set(_openmtr_ns_test [=[
        #include <sys/types.h>
        #include <netinet/in.h>
        #include <arpa/nameser.h>
        #include <resolv.h>
        int main() {
            unsigned char answer[512];
            ns_msg msg;
            int n = res_query("example.", ns_c_in, ns_t_txt, answer, sizeof(answer));
            return ns_initparse(answer, n, &msg);
        }]=])
    check_cxx_source_compiles("${_openmtr_ns_test}" OPENMTR_RESOLV_IN_LIBC)
    if(NOT OPENMTR_RESOLV_IN_LIBC)
        set(CMAKE_REQUIRED_LIBRARIES resolv)
        check_cxx_source_compiles("${_openmtr_ns_test}" OPENMTR_RESOLV_IN_LIBRESOLV)
        unset(CMAKE_REQUIRED_LIBRARIES)
        if(NOT OPENMTR_RESOLV_IN_LIBRESOLV)
            message(FATAL_ERROR "res_query()/ns_initparse() found neither in the C library nor in libresolv")
        endif()
        set(OPENMTR_RESOLV_LIBS resolv)
    endif()
endif()

function(openmtr_add_core target)
    target_sources(${target} PRIVATE ${OPENMTR_CORE_SOURCES})
    target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_BINARY_DIR})
    target_link_libraries(${target} PRIVATE jansson::jansson Threads::Threads ${OPENMTR_RESOLV_LIBS})
    if(WIN32)
        target_link_libraries(${target} PRIVATE
            ws2_32      # Winsock (address parsing, byte order)
            Iphlpapi    # IcmpSendEcho2 / Icmp6SendEcho2
            dnsapi      # DnsQuery_W (ASN TXT lookups)
            shell32     # CommandLineToArgvW (UTF-8 command line in cli.cpp)
        )
    endif()
    if(MSVC)
        # The sources hold UTF-8 text (in comments, e.g. cli.cpp's); without
        # this, MSVC reads them in the system code page and warns (C4819),
        # which the app's /WX turns into an error.
        target_compile_options(${target} PRIVATE /utf-8)
    endif()
endfunction()
