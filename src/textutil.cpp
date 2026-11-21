#include "textutil.h"

#include <climits>
#include <cstdint>

namespace textutil {

namespace {

// Length of the well-formed UTF-8 sequence starting at s[i], or 0 if the
// bytes there are not one (Unicode Table 3-7, "Well-Formed UTF-8 Byte
// Sequences": no overlong forms, no surrogates, nothing above U+10FFFF).
size_t sequenceLength(std::string_view s, size_t i)
{
    const auto byte = [&](size_t k) -> unsigned {
        return i + k < s.size() ? static_cast<unsigned char>(s[i + k]) : 0x100u;
    };
    const unsigned b0 = byte(0);
    if (b0 < 0x80)
        return 1;
    unsigned lo = 0x80, hi = 0xBF;     // allowed range of the second byte
    size_t   need;
    if (b0 >= 0xC2 && b0 <= 0xDF)      { need = 2; }
    else if (b0 == 0xE0)               { need = 3; lo = 0xA0; }
    else if (b0 >= 0xE1 && b0 <= 0xEC) { need = 3; }
    else if (b0 == 0xED)               { need = 3; hi = 0x9F; }   // no surrogates
    else if (b0 >= 0xEE && b0 <= 0xEF) { need = 3; }
    else if (b0 == 0xF0)               { need = 4; lo = 0x90; }
    else if (b0 >= 0xF1 && b0 <= 0xF3) { need = 4; }
    else if (b0 == 0xF4)               { need = 4; hi = 0x8F; }   // <= U+10FFFF
    else
        return 0;                      // C0, C1, F5..FF, or a stray continuation byte
    for (size_t k = 1; k < need; ++k) {
        const unsigned b = byte(k);
        if (b < (k == 1 ? lo : 0x80u) || b > (k == 1 ? hi : 0xBFu))
            return 0;
    }
    return need;
}

}  // namespace

std::string toValidUtf8(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        const size_t len = sequenceLength(s, i);
        if (len) {
            out.append(s.substr(i, len));
            i += len;
        } else {
            out += "\xEF\xBF\xBD";     // U+FFFD REPLACEMENT CHARACTER
            ++i;
        }
    }
    return out;
}

size_t utf16Length(std::string_view s)
{
    size_t units = 0;
    for (const char c : s) {
        const auto b = static_cast<unsigned char>(c);
        if ((b & 0xC0) == 0x80)
            continue;                  // continuation byte: counted with its lead
        units += (b >= 0xF0) ? 2 : 1;  // 4-byte sequences need a surrogate pair
    }
    return units;
}

std::string leftJustified(std::string_view s, size_t width)
{
    std::string out(s);
    const size_t len = utf16Length(s);
    if (len < width)
        out.append(width - len, ' ');
    return out;
}

std::string rightJustified(std::string_view s, size_t width)
{
    const size_t len = utf16Length(s);
    std::string out;
    if (len < width)
        out.assign(width - len, ' ');
    out.append(s);
    return out;
}

bool parseInt(std::string_view s, int& out)
{
    const auto isSpace = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
    };
    size_t b = 0, e = s.size();
    while (b < e && isSpace(s[b])) ++b;
    while (e > b && isSpace(s[e - 1])) --e;
    if (b == e)
        return false;
    bool negative = false;
    if (s[b] == '+' || s[b] == '-') {
        negative = (s[b] == '-');
        ++b;
    }
    if (b == e)
        return false;
    int64_t value = 0;
    for (size_t i = b; i < e; ++i) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        value = value * 10 + (s[i] - '0');
        if (value > static_cast<int64_t>(INT_MAX) + 1)
            return false;              // too long for an int either way
    }
    if (negative)
        value = -value;
    if (value < INT_MIN || value > INT_MAX)
        return false;
    out = static_cast<int>(value);
    return true;
}

std::string formatLocalTime(std::time_t t, const char* format)
{
    std::tm local{};
#ifdef _WIN32
    localtime_s(&local, &t);
#else
    localtime_r(&t, &local);
#endif
    char buf[64];
    const size_t n = std::strftime(buf, sizeof(buf), format, &local);
    return std::string(buf, n);
}

}  // namespace textutil
