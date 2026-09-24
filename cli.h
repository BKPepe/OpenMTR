// ==========================================================================
//  cli.h — headless report mode (OpenMTR --report ...)
//
//  Runs a trace without any window, like `mtr --report`: a fixed number of
//  probe cycles, then the report on stdout and an exit code scripts can act
//  on. See cli.cpp for the options and the exit codes.
// ==========================================================================

#pragma once

// True when the command line asks for report mode (or for --help /
// --version), which main() must then run instead of the window. Decided
// before any Qt application object exists: report mode creates a
// QCoreApplication, never a QApplication, so it needs no display.
bool isReportModeRequested(int argc, char* argv[]);

// Run report mode to completion and return the process exit code.
int runReportMode(int argc, char* argv[]);
