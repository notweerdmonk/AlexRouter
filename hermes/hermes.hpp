/*
 * hermes - codec and parser library
 * Copyright (C) 2026 notweerdmonk
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

#ifndef _HERMES_H_
#define _HERMES_H_

#include <array>
#include <vector>
#include <unordered_map>
#include <algorithm>

namespace hermes {

  template<typename T, std::size_t N>
  struct array : public std::array<T, N> {
    public:
#if __cplusplus <= 201402L
    array(const std::array<T, N> &arr) : std::array<T,N>(arr) {
    }
#endif

    bool contains(T element) const {
      auto it = std::find(this->begin(), this->end(), element);
      return it != this->end();
    }
  };

  int pow(int x, int y) {

    if (x == 1 || y == 0) {
      return 1;
    }

    if (y % 2 == 0) {
      return pow(x * x, y/2);
    }

    return x * pow(x * x, y/2);
  }

  int atoi(const char *str, int base) {
    bool neg = false;
    int n = 0;
    const char *ptr = str;
    std::size_t highest = 0;

    while (*ptr != '\0' &&
        (*ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n')) {
      ptr++;
    }

    if (*ptr == '\0') {
      return n;
    }

    if (*ptr == '+') {
      ptr++;
    } else if (*ptr == '-') {
      ptr++;
      neg = true;
    }

    while (*ptr != '\0'
        && *ptr >= '0'
        && *ptr <= '9') {
      ptr++;
      highest++;
    }

    for (std::size_t i = 0; i <= highest; i++) {
      n += (*--ptr - '0') * pow(base, i);
    }

    return neg ? -n : n;
  }

  unsigned int atou(const char *str, int base) {
    unsigned int n = 0;
    const char *ptr = str;
    std::size_t highest = 0;

    while (*ptr != '\0' &&
        (*ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n')) {
      ptr++;
    }

    if (*ptr == '\0') {
      return n;
    }

    if (*ptr == '+') {
      ptr++;
    } else if (*ptr == '-') {
      return n;
    }

    while ( *ptr != '\0' &&
        ( (*ptr >= '0' && *ptr <= '9') ||
          (*ptr >= 'a' && *ptr <= 'f') ||
          (*ptr >= 'A' && *ptr <= 'f') ) ) {
      ptr++;
      highest++;
    }

    for (std::size_t i = 0; i < highest; i++) {
      if (*--ptr >= '0' && *ptr <= '9') {
        n += (*ptr - '0') * pow(base, i);
      } else if (*ptr >= 'a' && *ptr <= 'f') {
        n += (*ptr - 'a' + 10) * pow(base, i);
      } else if (*ptr >= 'A' && *ptr <= 'F') {
        n += (*ptr - 'A' + 10) * pow(base, i);
      } else {
        return 0;
      }
    }

    return n;
  }

  namespace percent {

    template <
      typename chartype = char,
      typename strtype_in = std::basic_string<chartype>,
      typename strtype_out = std::basic_string<chartype>
    >
    std::size_t encode(const strtype_in &in, strtype_out &out) {
#if __cplusplus > 201402L
      const array<chartype, 20> enc_chars({
        ':', '/', '?', '#', 
        '[', ']', '@', '!',
        '$', '&', '\'', '(',
        ')', '*', '+', ',',
        ';', '=', '%', ' '
      });
#else
      const array<chartype, 20> enc_chars(std::array<chartype, 20>{
        ':', '/', '?', '#', 
        '[', ']', '@', '!',
        '$', '&', '\'', '(',
        ')', '*', '+', ',',
        ';', '=', '%', ' '
      });
#endif

      out.clear();

      typename strtype_in::const_iterator it = in.cbegin();
      while (it < in.cend()) {
        chartype c = *it;
        if (enc_chars.contains(c)) {
          chartype enc[4] = {
            '%',
            '\0',
            '\0',
            '\0'
          };

          int ord = static_cast<int>(c);

          for (unsigned char i = 2; i > 0 && ord > 0;) {
            enc[i--] = (ord % 16)["0123456789ABCDEF"];
            ord = ord / 16;
          }

          out += enc;

        } else {
          out += c;
        }
        ++it;

      }

      return out.length();


      return 0;
    }

    template <
      typename chartype = char,
      typename strtype = std::basic_string<chartype>
    >
    std::size_t encode(strtype &str) {
      strtype out;
      auto ret = encode(str, out);
      if (ret) {
        str = out;
      }
      return ret;
    }

    template <
      typename chartype = char,
      typename strtype_in = std::basic_string<chartype>,
      typename strtype_out = std::basic_string<chartype>
    >
    std::size_t decode(const strtype_in &in, strtype_out &out) {
      out.clear();

      typename strtype_in::const_iterator it = in.cbegin();
      while (it < in.cend()) {
        chartype c = *it;
        if (c == '%') {
          chartype hex[3] = {
            *(it + 1),
            *(it + 2),
            '\0'
          };

          out += static_cast<chartype>(atou(hex, 16));
          it += 3;

        } else {
          out += c;
          ++it;
        }
      }

      return it - in.cbegin();
    }

    template <
      typename chartype = char,
      typename strtype = std::basic_string<chartype>
    >
    std::size_t decode(strtype &data) {
      strtype out;
      auto ret = decode<chartype, strtype, strtype>(
          strtype(data.data(), data.size()),
          out
      );
      if (ret) {
        data = out;
      }
      return ret;
    }

    template <
      typename chartype = char,
      typename strtype_in = std::basic_string<chartype>,
      typename strtype_out = std::basic_string<chartype>
    >
    std::size_t streamdecode(
        const strtype_in &in,
        strtype_out &out,
        bool reset
    ) {

      static unsigned char hex[3] = { 0 };
      static unsigned char idx = -1;

      if (reset) {
        idx = -1;
      }

      out.clear();

      typename strtype_in::const_iterator it = in.cbegin();
      while (it < in.cend()) {
        if (idx < 2) {
          for (unsigned char i = idx; i < 2; ++i) {
            hex[idx++] = *it++;
            if (it == in.cend()) {
              return it - in.cbegin();
            }
          }
          hex[idx] = '\0';

          out += static_cast<chartype>(atou(hex, 16));

          continue;
        }

        if (*it == '%') {
          for (idx = 0; idx < 2; ++idx) {
            if (++it == in.cend()) {
              return it - in.cbegin();
            }
            hex[idx] = *it;
          }
          hex[idx] = '\0';


          out += static_cast<chartype>(atou(hex, 16));
          ++it;

        } else {
          out += *it++;
        }
      }

      return it - in.cbegin();
    }

  }; /* namespace percent */

  namespace url {

    template <
      typename chartype = char,
      typename strtype_in = std::basic_string<chartype>,
      typename strtype_out = std::basic_string<chartype>,
      typename hash = std::hash<strtype_out>,
      typename equal = std::equal_to<strtype_out>
    >
    std::size_t streamdecode(
        const strtype_in &in,
        std::unordered_map<strtype_out, strtype_out, hash, equal> &out,
        const bool reset = false,
        const bool querystr = true
    ) {

      using pos_type = typename strtype_in::size_type;

      static bool field_name_found = false;
      static std::basic_string<chartype> field_name;
      static std::basic_string<chartype> field_data;

      static typename strtype_in::size_type start = 0;
      static typename strtype_in::size_type n = 0;

      out.clear();

      if (reset) {
        start = n = 0;
        field_name_found = false;
        field_name.clear();
        field_data.clear();
      }

      std::size_t ret = 0;

      std::vector<std::pair<pos_type, pos_type>> pairs;

      typename strtype_in::size_type i = 0;
      const typename strtype_in::size_type cend = in.length();

      while (i <= cend) {
        chartype c = in[i];

        if (c == '&' || i == cend) {
          if (i == cend && !field_name_found) {

            strtype_out field_data_decoded;
            /* field_name stores characters until '=' is found */
            ret += percent::decode(field_name, field_data_decoded);

            if (querystr) {
              out[field_data_decoded] = field_data_decoded;
            } else {
              out[reinterpret_cast<const chartype*>("")] +=
                field_data_decoded;
            }

          } else if (field_name_found) {
            strtype_out field_name_decoded;
            ret += percent::decode(field_name, field_name_decoded);

            strtype_out field_data_decoded;
            ret += percent::decode(field_data, field_data_decoded);

            out[field_name_decoded] = field_data_decoded;

            field_name_found = false;
            field_name.clear();
            field_data.clear();
          }

          start = n + 1;

        } else if (c == '=') {
          if (start < n) {
            field_name_found = true;

          }

        } else if (field_name_found) {
          field_data += c;

        } else {
          field_name += c;

        }
        ++n;
        ++i;
      }

      return ret;
    }

    template <
      typename chartype = char,
      typename strtype_in = std::basic_string<chartype>,
      typename strtype_out = std::basic_string<chartype>,
      typename hash = std::hash<strtype_out>,
      typename equal = std::equal_to<strtype_out>
    >
    std::size_t decode(
        const strtype_in &in,
        std::unordered_map<strtype_out, strtype_out, hash, equal> &out,
        const bool querystr = true
    ) {

      out.clear();

      std::size_t ret = 0;

      using pos_type = typename strtype_in::size_type;
      using mutable_string_view =
        struct {
          const chartype *p;
          typename strtype_in::size_type n;
        };

      std::vector<std::pair<pos_type, pos_type>> pairs;

      bool field_name_found = false;
      mutable_string_view field_name{nullptr, 0};
      mutable_string_view field_data{nullptr, 0};

      typename strtype_in::size_type i = 0;
      typename strtype_in::size_type start = 0;
      const typename strtype_in::size_type cend = in.length();

      while (i <= cend) {
        chartype c = in[i];

        if (c == '&' || i == cend) {
          if (i == cend && !field_name_found) {

            strtype_out field_data_decoded;
            ret += percent::decode(
                strtype_in{in.data() + start, i - start},
                field_data_decoded
            );

            if (querystr) {
              out[field_data_decoded] = field_data_decoded;
            } else {
              out[reinterpret_cast<const chartype*>("")] +=
                field_data_decoded;
            }

          } else if (field_name_found) {
            strtype_out field_name_decoded;
            ret += percent::decode(
                strtype_in{field_name.p, field_name.n},
                field_name_decoded
            );

            /* field_data.n stores the index after '=' */
            field_data.n = i - field_data.n;

            strtype_out field_data_decoded;
            ret += percent::decode(
                strtype_in{field_data.p, field_data.n},
                field_data_decoded
            );

            out[field_name_decoded] = field_data_decoded;

            field_name_found = false;
          }
          start = i + 1;

        } else if (c == '=') {
          if (start < i) {
            field_name.p = in.data() + start;
            field_name.n = i - start;
            field_name_found = true;

            field_data.p = in.data() + i + 1;
            field_data.n = i + 1; // Repurpose length to store starting index
          }
        }
        ++i;
      }

      return ret;
    }

  }; /* namespace url */

  namespace utf32 {

    template <
      typename chartype = char,
      typename strtype = std::basic_string<chartype>
    >
    std::u32string decode(const strtype &utf8_str) {

      using bytetype = unsigned char;

      std::u32string result;
      std::size_t i = 0;

      while (i < utf8_str.size()) {
        uint32_t code_point = 0;
        bytetype c = static_cast<bytetype>(utf8_str[i]);

        if (c <= 0x7F) {
          /* 1-byte sequence (ASCII) */
          code_point = c;
          i += 1;
        } else if ((c & 0xE0) == 0xC0) {
          /* 2-byte sequence */
          code_point = (c & 0x1F) << 6;
          code_point |= (utf8_str[i + 1] & 0x3F);
          i += 2;
        } else if ((c & 0xF0) == 0xE0) {
          /* 3-byte sequence */
          code_point = (c & 0x0F) << 12;
          code_point |= (utf8_str[i + 1] & 0x3F) << 6;
          code_point |= (utf8_str[i + 2] & 0x3F);
          i += 3;
        } else if ((c & 0xF8) == 0xF0) {
          /* 4-byte sequence */
          code_point = (c & 0x07) << 18;
          code_point |= (utf8_str[i + 1] & 0x3F) << 12;
          code_point |= (utf8_str[i + 2] & 0x3F) << 6;
          code_point |= (utf8_str[i + 3] & 0x3F);
          i += 4;
        } else {
          /* Invalid byte or unsupported encoding, skip it */
          i += 1;
        }

        result += code_point;
      }

      return result;
    }

    template <
      typename chartype = char,
      typename strtype = std::basic_string<chartype>
    >
    strtype encode(char32_t code_point) {
      strtype result;

      if (code_point <= 0x7F) {
        /* 1-byte sequence (ASCII) */
        result += static_cast<chartype>(code_point);
      } else if (code_point <= 0x7FF) {
        /* 2-byte sequence */
        result += static_cast<chartype>(0xC0 | (code_point >> 6));
        result += static_cast<chartype>(0x80 | (code_point & 0x3F));
      } else if (code_point <= 0xFFFF) {
        /* 3-byte sequence */
        result += static_cast<chartype>(0xE0 | (code_point >> 12));
        result += static_cast<chartype>(0x80 | ((code_point >> 6) & 0x3F));
        result += static_cast<chartype>(0x80 | (code_point & 0x3F));
      } else if (code_point <= 0x10FFFF) {
        /* 4-byte sequence */
        result += static_cast<chartype>(0xF0 | (code_point >> 18));
        result += static_cast<chartype>(0x80 | ((code_point >> 12) & 0x3F));
        result += static_cast<chartype>(0x80 | ((code_point >> 6) & 0x3F));
        result += static_cast<chartype>(0x80 | (code_point & 0x3F));
      }



      return result;
    }

    template <
      typename chartype = char,
      typename strtype = std::basic_string<chartype>
    >
    strtype encode(const std::u32string &utf32_str) {
      strtype utf8_str;

      for (auto code_point : utf32_str) {
        utf8_str += utf32::encode(code_point);
      }

      return utf8_str;
    }

  }; /* namespace utf32 */

}; /* namespace hermes */

#endif /* _HERMES_H_ */
