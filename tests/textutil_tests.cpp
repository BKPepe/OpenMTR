// ==========================================================================
//  textutil_tests.cpp — src/textutil.h behaves like the QString code it
//  replaced
//
//  The expectations are QtCore's own answers (checked against Qt 6.4.2 with
//  a differential test over 200 000 random inputs): QString::toInt(),
//  QString::fromUtf8()'s repair of invalid UTF-8, QString::length() and
//  leftJustified()/rightJustified().
// ==========================================================================

#include "textutil.h"

#include <climits>
#include <cstdio>
#include <string>

using namespace textutil;

static int g_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

static bool parses(const char* s, int expected)
{
    int v = 0;
    return parseInt(s, v) && v == expected;
}

static bool rejects(const std::string& s)
{
    int v = 12345;
    return !parseInt(s, v) && v == 12345;
}

static void parse_int()
{
    CHECK(parses("42", 42));
    CHECK(parses(" 42", 42));
    CHECK(parses("42 ", 42));
    CHECK(parses("\t42\n", 42));
    CHECK(parses("\v7\f", 7));
    CHECK(parses("+42", 42));
    CHECK(parses("-42", -42));
    CHECK(parses("007", 7));
    CHECK(parses("-0", 0));
    CHECK(parses("2147483647", INT_MAX));
    CHECK(parses("-2147483648", INT_MIN));
    CHECK(rejects("2147483648"));
    CHECK(rejects("-2147483649"));
    CHECK(rejects("99999999999999999999"));
    CHECK(rejects(""));
    CHECK(rejects("  "));
    CHECK(rejects("+"));
    CHECK(rejects("-"));
    CHECK(rejects("--1"));
    CHECK(rejects("1e3"));
    CHECK(rejects("12.5"));
    CHECK(rejects("42abc"));
    CHECK(rejects("0x1A"));
    CHECK(rejects("1 2"));
    CHECK(rejects("23028 1234"));            // a multi-origin ASN stays text
    CHECK(rejects("\xC2\xA0" "42"));         // no-break space is not trimmed
    CHECK(rejects("\xD9\xA4\xD9\xA2"));      // Arabic-Indic digits are not digits
}

static void utf8_repair()
{
    const std::string fffd = "\xEF\xBF\xBD";
    CHECK(toValidUtf8("plain") == "plain");
    CHECK(toValidUtf8("caf\xC3\xA9 \xF0\x9F\x98\x80") == "caf\xC3\xA9 \xF0\x9F\x98\x80");
    CHECK(toValidUtf8("\xFF") == fffd);
    CHECK(toValidUtf8("a\x80" "b") == "a" + fffd + "b");
    // One replacement per byte of an incomplete or invalid sequence, as Qt.
    CHECK(toValidUtf8("\xE2\x80x") == fffd + fffd + "x");
    CHECK(toValidUtf8("\xF0\x9F\x98") == fffd + fffd + fffd);
    CHECK(toValidUtf8("\xED\xA0\x80") == fffd + fffd + fffd);      // a surrogate
    CHECK(toValidUtf8("\xC0\x80") == fffd + fffd);                 // overlong
    CHECK(toValidUtf8("\xF4\x90\x80\x80") == fffd + fffd + fffd + fffd);   // > U+10FFFF
    CHECK(toValidUtf8("\xE2(\xA1") == fffd + "(" + fffd);
}

static void widths()
{
    CHECK(utf16Length("") == 0);
    CHECK(utf16Length("abc") == 3);
    CHECK(utf16Length("caf\xC3\xA9") == 4);
    CHECK(utf16Length("\xE2\x80\xA8") == 1);           // U+2028: one unit
    CHECK(utf16Length("\xF0\x9F\x98\x80") == 2);       // outside the BMP: a pair
    CHECK(leftJustified("ab", 4) == "ab  ");
    CHECK(rightJustified("ab", 4) == "  ab");
    CHECK(leftJustified("caf\xC3\xA9", 5) == "caf\xC3\xA9 ");
    CHECK(rightJustified("abcdef", 3) == "abcdef");     // never truncated
    CHECK(leftJustified("", 0).empty());
}

int main()
{
    parse_int();
    utf8_repair();
    widths();
    if (g_failures)
        std::printf("%d check(s) failed\n", g_failures);
    return g_failures ? 1 : 0;
}
