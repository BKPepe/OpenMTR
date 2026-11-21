// ==========================================================================
//  cli_args_tests.cpp — the report-mode command line (cli::parseArgs)
//
//  The options, order rules and error texts of `OpenMTR --report` as 1.4.0
//  parsed them with QString, now with std::string: every case here behaves
//  as it did then. Runs on every OS.
// ==========================================================================

#include "cli.h"

#include <cstdio>
#include <initializer_list>
#include <string>
#include <vector>

using cli::OutputFormat;
using cli::ParseResult;

static int g_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

struct Parsed {
    ParseResult  result;
    cli::Options opts;
    std::string  error;
};

static Parsed parse(std::initializer_list<const char*> args)
{
    std::vector<std::string> storage = { "OpenMTR" };
    for (const char* a : args)
        storage.emplace_back(a);
    std::vector<char*> argv;
    for (std::string& s : storage)
        argv.push_back(s.data());
    argv.push_back(nullptr);
    Parsed p;
    p.result = cli::parseArgs(static_cast<int>(storage.size()), argv.data(), p.opts, p.error);
    return p;
}

static bool usage(std::initializer_list<const char*> args, const std::string& error)
{
    const Parsed p = parse(args);
    if (p.result != ParseResult::Usage || p.error != error) {
        std::printf("  got result %d, error \"%s\"; expected \"%s\"\n",
                    static_cast<int>(p.result), p.error.c_str(), error.c_str());
        return false;
    }
    return true;
}

static void valid()
{
    {
        const Parsed p = parse({ "--report", "--time", "10", "example.com" });
        CHECK(p.result == ParseResult::Run);
        CHECK(p.opts.target == "example.com");
        CHECK(p.opts.timeSeconds == 10);
        CHECK(p.opts.pingSize == 64);
        CHECK(p.opts.ipVersion == 6);
        CHECK(p.opts.format == OutputFormat::Text);
        CHECK(p.opts.outputPath.empty());
    }
    {
        // The target anywhere; --report optional to the parser; every option.
        const Parsed p = parse({ "1.1.1.1", "--json", "-4", "--size", "128", "--time", "3",
                                 "--output", "out.json" });
        CHECK(p.result == ParseResult::Run);
        CHECK(p.opts.target == "1.1.1.1");
        CHECK(p.opts.format == OutputFormat::Json);
        CHECK(p.opts.ipVersion == 4);
        CHECK(p.opts.pingSize == 128);
        CHECK(p.opts.timeSeconds == 3);
        CHECK(p.opts.outputPath == "out.json");
    }
    CHECK(parse({ "--csv", "--time", "1", "h" }).opts.format == OutputFormat::Csv);
    CHECK(parse({ "--txt", "--time", "1", "h" }).opts.format == OutputFormat::Text);
    CHECK(parse({ "-4", "-6", "--time", "1", "h" }).opts.ipVersion == 6);   // last one wins
    CHECK(parse({ "--time", " 7", "h" }).opts.timeSeconds == 7);           // as QString::toInt
    CHECK(parse({ "--time", "+7", "h" }).opts.timeSeconds == 7);
    CHECK(parse({ "--size", "64", "--time", "1", "h" }).opts.pingSize == 64);
    CHECK(parse({ "--size", "8192", "--time", "1", "h" }).opts.pingSize == 8192);
    CHECK(parse({ "--time", "1", "--time", "2", "h" }).opts.timeSeconds == 2);
    CHECK(parse({ "--output", "-x", "--time", "1", "h" }).opts.outputPath == "-x");   // a value, not an option
}

static void help()
{
    CHECK(parse({ "-h" }).result == ParseResult::Help);
    CHECK(parse({ "--h" }).result == ParseResult::Help);
    CHECK(parse({ "--help" }).result == ParseResult::Help);
    CHECK(parse({ "--report", "--help", "--bogus" }).result == ParseResult::Help);
    CHECK(parse({ "--time", "5", "h", "-h" }).result == ParseResult::Help);
}

static void errors()
{
    CHECK(usage({ "example.com" }, "--time <seconds> is required"));
    CHECK(usage({ "--time", "5" }, "A target is required"));
    CHECK(usage({ "--time", "5", "a", "b" }, "Only one target may be given"));
    CHECK(usage({ "--time" }, "--time needs a value"));
    CHECK(usage({ "--time", "5", "h", "--size" }, "--size needs a value"));
    CHECK(usage({ "--time", "5", "h", "--output" }, "--output needs a path"));
    CHECK(usage({ "--time", "0", "h" }, "--time must be a positive number of seconds"));
    CHECK(usage({ "--time", "-5", "h" }, "--time must be a positive number of seconds"));
    CHECK(usage({ "--time", "abc", "h" }, "--time must be a positive number of seconds"));
    CHECK(usage({ "--time", "1e3", "h" }, "--time must be a positive number of seconds"));
    CHECK(usage({ "--time", "5", "--size", "63", "h" }, "--size must be between 64 and 8192"));
    CHECK(usage({ "--time", "5", "--size", "8193", "h" }, "--size must be between 64 and 8192"));
    CHECK(usage({ "--json", "--csv", "--time", "5", "h" }, "--txt, --json and --csv are mutually exclusive"));
    CHECK(usage({ "--json", "--json", "--time", "5", "h" }, "--txt, --json and --csv are mutually exclusive"));
    CHECK(usage({ "--bogus", "--time", "5", "h" }, "Unknown option: --bogus"));
    CHECK(usage({ "--bogus", "--help" }, "Unknown option: --bogus"));    // the first problem wins
    CHECK(usage({ "-x", "--time", "5", "h" }, "Unknown option: -x"));
    CHECK(usage({ "--time=5", "h" }, "Unknown option: --time=5"));
    CHECK(usage({ "--tim", "5", "h" }, "Unknown option: --tim"));        // no abbreviations
    CHECK(usage({ "--time", "5", "-" }, "Unknown option: -"));
}

int main()
{
    valid();
    help();
    errors();
    if (g_failures)
        std::printf("%d check(s) failed\n", g_failures);
    return g_failures ? 1 : 0;
}
