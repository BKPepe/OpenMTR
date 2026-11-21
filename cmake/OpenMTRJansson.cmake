# ============================================================================
#  cmake/OpenMTRJansson.cmake — the JSON library, as the target jansson::jansson
#
#  The JSON report is written with jansson (MIT licence; packaged by every
#  major Linux distribution, Homebrew, vcpkg and OpenWrt core, where it is
#  already on every router image). OPENMTR_JANSSON says where it comes from:
#
#    system   the one installed on the build system (CMake package or
#             pkg-config); an error if there is none. For packagers.
#    bundled  a pinned release, downloaded at configure time, checked
#             against its SHA-256 and linked statically. What release builds
#             use, so that nothing installed on a CI runner can end up in a
#             shipped binary, and nothing new needs to ship beside it.
#    auto     system if found, else bundled (the default).
# ============================================================================

set(OPENMTR_JANSSON "auto" CACHE STRING "Where jansson comes from: auto, system or bundled")
set_property(CACHE OPENMTR_JANSSON PROPERTY STRINGS auto system bundled)
if(NOT OPENMTR_JANSSON MATCHES "^(auto|system|bundled)$")
    message(FATAL_ERROR "OPENMTR_JANSSON must be auto, system or bundled, not \"${OPENMTR_JANSSON}\"")
endif()

if(NOT OPENMTR_JANSSON STREQUAL "bundled")
    # No version in the call: jansson's CMake package carries its library
    # version (4.x for jansson 2.x) with ExactVersion compatibility, so
    # asking for any version would quietly fail.
    find_package(jansson CONFIG QUIET)
    if(NOT TARGET jansson::jansson)
        # Debian/Ubuntu's libjansson-dev installs only jansson.pc.
        find_package(PkgConfig QUIET)
        if(PKG_CONFIG_FOUND)
            pkg_check_modules(OPENMTR_JANSSON_PC QUIET IMPORTED_TARGET GLOBAL "jansson>=2.13")
            if(OPENMTR_JANSSON_PC_FOUND)
                add_library(jansson::jansson ALIAS PkgConfig::OPENMTR_JANSSON_PC)
            endif()
        endif()
    endif()
    if(TARGET jansson::jansson)
        message(STATUS "jansson: system")
    endif()
endif()

if(NOT TARGET jansson::jansson)
    if(OPENMTR_JANSSON STREQUAL "system")
        message(FATAL_ERROR "OPENMTR_JANSSON=system, but no jansson (2.13 or newer) was found")
    endif()
    message(STATUS "jansson: bundled 2.15.1, linked statically")
    include(FetchContent)
    foreach(option JANSSON_BUILD_SHARED_LIBS JANSSON_EXAMPLES JANSSON_BUILD_DOCS
                   JANSSON_INSTALL JANSSON_COVERAGE)
        set(${option} OFF CACHE BOOL "" FORCE)
    endforeach()
    set(JANSSON_WITHOUT_TESTS ON CACHE BOOL "" FORCE)
    # Off: jansson would otherwise seed its hash function on Windows through
    # GetProcAddress(CryptGenRandom) (hashtable_seed.c) — a dynamic API
    # lookup the AV hardening rules keep out of the binary. It falls back to
    # the time and process id, which is plenty for a seed against
    # hash-flooding the few keys a report has.
    set(USE_WINDOWS_CRYPTOAPI OFF CACHE BOOL "" FORCE)
    # jansson declares CMake 3.10, which predates CMAKE_MSVC_RUNTIME_LIBRARY
    # (policy CMP0091); make it honour the CRT the app is built with
    # (static /MT in release CI) instead of the /MD default.
    set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
    FetchContent_Declare(jansson
        URL      https://github.com/akheron/jansson/releases/download/v2.15.1/jansson-2.15.1.tar.gz
        # The same archive and hash as OpenWrt's package/libs/jansson.
        URL_HASH SHA256=0c7114dc0b2d22a670724a1f95922029d7077c19dbf79a584cb8084d2f267f2f
    )
    FetchContent_MakeAvailable(jansson)
    unset(CMAKE_POLICY_DEFAULT_CMP0091)
    if(MSVC)
        # Control Flow Guard needs every object instrumented, the library's too.
        target_compile_options(jansson PRIVATE /guard:cf)
    endif()
endif()
