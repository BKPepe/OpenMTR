// ==========================================================================
//  versioninfo.h — the app's version line (GUI + CLI)
// ==========================================================================

#pragma once

#include <string>

// "1.4.0 (AMD64)": the version and the CPU architecture it was built for;
// in the window app with its Qt version appended ("1.4.0 (AMD64) · Qt
// 6.12.0"). Used identically by MainWindow's About dialog and `--version`,
// so the two can never show different text for the same build.
std::string openMtrVersionLine();
