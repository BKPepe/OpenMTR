// ==========================================================================
//  cli.h — headless report mode (`OpenMTR --report ...`)
// ==========================================================================

#pragma once

#include <string>

namespace cli {

// Parses argv, runs a trace and prints one report to stdout, then returns
// a process exit code (see cli.cpp for the full list). Never touches Qt
// (it is part of the Qt-free core) and never constructs a QApplication —
// main.cpp calls this *instead of* creating the GUI when "--report" is
// present on the command line, so this path works with no display at all
// (SSH, cron, CI).
int run(int argc, char** argv);

// Prints the one-line version (same text as the About dialog) to stdout and
// returns the process exit code. Lives here rather than in main.cpp because
// on Windows even this needs the console-vs-redirected-output handling
// (writeText in cli.cpp) that non-ASCII characters in that text require.
int printVersion();

// ---- Command line (exposed for tests/cli_args_tests.cpp) -------------------

enum class OutputFormat { Text, Json, Csv };

struct Options {
    std::string  target;
    int          timeSeconds = 0;
    unsigned     pingSize    = 64;     // same default as the window's spin box
    int          ipVersion   = 6;      // preferred family, 4 or 6 (the window's IPv6 checkbox)
    OutputFormat format      = OutputFormat::Text;
    std::string  outputPath;           // empty = stdout
};

enum class ParseResult {
    Run,        // `opts` holds a complete, valid request
    Help,       // -h / --h / --help
    Usage,      // invalid; `error` says why (run() prints it and the usage)
};

// Parses the report-mode command line: the same options, order rules and
// messages as before it became Qt-free (main() answers -v/--version before
// this is reached). Prints nothing. `argv` is UTF-8 (run() converts it on
// Windows).
ParseResult parseArgs(int argc, char** argv, Options& opts, std::string& error);

}  // namespace cli
