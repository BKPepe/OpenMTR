// ==========================================================================
//  textutil.h — the few text operations the reports need, without Qt
//
//  report_core builds its reports from UTF-8 std::strings. These helpers
//  give them exactly the behaviour the QString code they replace had —
//  column widths counted in UTF-16 code units (QString::length()), padding
//  that never truncates (leftJustified/rightJustified), integers parsed
//  like QString::toInt(), invalid UTF-8 repaired like QString::fromUtf8() —
//  so the reports stay byte for byte what they were (tests/golden/).
// ==========================================================================

#pragma once

#include <cstddef>
#include <ctime>
#include <string>
#include <string_view>

namespace textutil {

// `s` with every byte that does not belong to a well-formed UTF-8 sequence
// replaced by U+FFFD — one replacement per byte, exactly as
// QString::fromUtf8() does it. Host names from a reverse lookup are raw
// bytes on POSIX; JSON and the GUI need valid UTF-8.
std::string toValidUtf8(std::string_view s);

// Length of valid UTF-8 `s` in UTF-16 code units — QString::length() of
// the same text (a character outside the BMP counts twice), which is what
// the text report's column widths have always been measured in.
size_t utf16Length(std::string_view s);

// `s` followed (leftJustified) or preceded (rightJustified) by spaces up to
// `width` UTF-16 code units; never shortened. QString::leftJustified() and
// rightJustified() with truncate = false.
std::string leftJustified(std::string_view s, size_t width);
std::string rightJustified(std::string_view s, size_t width);

// A base-10 int exactly as QString::toInt() accepts one: optional ASCII
// whitespace around it, an optional sign, ASCII digits only, within the
// range of int. False (and `out` unchanged) otherwise.
bool parseInt(std::string_view s, int& out);

// `t` as local time, formatted by strftime() with `format`.
std::string formatLocalTime(std::time_t t, const char* format);

}  // namespace textutil
