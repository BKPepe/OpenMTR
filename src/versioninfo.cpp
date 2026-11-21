#include "versioninfo.h"
#include "version.h"

// The architecture names QSysInfo::buildCpuArchitecture() gives, upper-cased,
// with x86_64 called AMD64 — what this line has always shown — decided by
// the compiler's own target macros instead of asking Qt.
#if defined(__x86_64__) || defined(_M_X64)
#define OPENMTR_ARCH "AMD64"
#elif defined(__i386__) || defined(_M_IX86)
#define OPENMTR_ARCH "I386"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define OPENMTR_ARCH "ARM64"
#elif defined(__arm__) || defined(_M_ARM)
#define OPENMTR_ARCH "ARM"
#elif defined(__mips64)
#define OPENMTR_ARCH "MIPS64"
#elif defined(__mips__)
#define OPENMTR_ARCH "MIPS"
#elif defined(__powerpc64__)
#define OPENMTR_ARCH "POWER64"
#elif defined(__powerpc__)
#define OPENMTR_ARCH "POWER"
#elif defined(__riscv) && __riscv_xlen == 64
#define OPENMTR_ARCH "RISCV64"
#elif defined(__riscv)
#define OPENMTR_ARCH "RISCV32"
#elif defined(__loongarch__) && __loongarch_grlen == 64
#define OPENMTR_ARCH "LOONGARCH64"
#elif defined(__s390x__)
#define OPENMTR_ARCH "S390X"
#else
#define OPENMTR_ARCH "UNKNOWN"
#endif

std::string openMtrVersionLine()
{
#ifdef OPENMTR_QT_VERSION
    // The window app (CMakeLists.txt defines this for its target only).
    return OPENMTR_VERSION " (" OPENMTR_ARCH ") \xC2\xB7 Qt " OPENMTR_QT_VERSION;   // U+00B7
#else
    return OPENMTR_VERSION " (" OPENMTR_ARCH ")";
#endif
}
