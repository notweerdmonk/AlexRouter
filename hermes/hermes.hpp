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

namespace hermes {

  int pow(int x, int y) {

    if (x == 1 || y == 0) {
      return 1;
    }

    if (y % 2 == 0) {
      return pow(x * x, y/2);
    }

    return x * pow(x * x, y/2);
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

  template <
    typename strtype_in = std::basic_string<char>,
    typename strtype_out = std::basic_string<char>
  >
  std::size_t percent_decode(const strtype_in &in, strtype_out &out) {
    out.clear();

    typename strtype_in::const_iterator it = in.cbegin();
    while (it < in.cend()) {
      char c = *it;
      if (c == '%') {
        char hex[3] = {
          *(1 + it),
          *(it + 2),
          '\0'
        };

        out.append(1, static_cast<char>(atou(hex, 16)));
        it += 3;

      } else {
        out.append(1, *it);
        it++;
      }

    }

    return it - in.cbegin();
  }

  template <typename strtype = std::basic_string<char>>
  std::size_t percent_decode(strtype &data) {
    strtype out;
    auto ret =
      percent_decode<strtype, strtype>(strtype(data.data(), data.size()), out);
    data = out;
    return ret;
  }

  template <
    typename chartype = char,
    typename strtype_in = std::basic_string<chartype>,
    typename strtype_out = std::basic_string<chartype>,
    typename hash = std::hash<strtype_out>,
    typename equal = std::equal_to<strtype_out>
  >
  std::size_t url_decode(
      const strtype_in &in,
      std::unordered_map<strtype_out, strtype_out, hash, equal> &out
  ) {

    std::size_t ret = 0;

    out.clear();

    using pos_type = typename strtype_in::size_type;
    std::vector<std::pair<pos_type, pos_type>> pairs;

    typename strtype_in::size_type i = 0;
    typename strtype_in::size_type start = 0;
    constexpr typename strtype_in::size_type cbegin = 0;
    const typename strtype_in::size_type cend = in.length();
    while (i < cend) {
      chartype c = in[i];

      if (c == '&') {
        pos_type a = start - cbegin;
        pos_type b = i - cbegin;
        start = i + 1;
        if (a < b) {
          pairs.push_back({a, b});
        }
      }
      ++i;
    }
    pos_type a = start - cbegin;
    pos_type b = i - cbegin;
    if (a < b) {
      pairs.push_back({a, b});
    }

    for (auto &p : pairs) {
      typename strtype_in::size_type i = p.first;
      const typename strtype_in::size_type start = i;
      const typename strtype_in::size_type end = p.second;
      while (i != end) {
        if (in[i] == '=') {
          break;
        }
        ++i;
      }
      if (i == end) {
        strtype_in field_data(in.data() + start, end - start);
        strtype_out field_data_decoded;

        ret += percent_decode(field_data, field_data_decoded);
        out[reinterpret_cast<const chartype*>("")] +=
          field_data_decoded;

      } else if (in[i] == '=') {
        const strtype_out field_name(in.data() + start, i - start);

        strtype_in field_data(in.data() + i + 1, end - i - 1);
        ret += i - start + 1;

        strtype_out field_data_decoded;
        ret += percent_decode(field_data, field_data_decoded);
        out[field_name] = field_data_decoded;
      }
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
  std::size_t query_decode(
      const strtype_in &in,
      std::unordered_map<strtype_out, strtype_out, hash, equal> &out,
      const bool querystr = true
  ) {

    std::size_t ret = 0;

    out.clear();

    using pos_type = typename strtype_in::size_type;
    using mutable_string_view =
      struct {
        const chartype *p;
        typename strtype_in::size_type n;
      };
    std::vector<std::pair<pos_type, pos_type>> pairs;

    typename strtype_in::size_type i = 0;
    typename strtype_in::size_type start = 0;
    const typename strtype_in::size_type cend = in.length();
    bool field_name_found = false;
    mutable_string_view field_name{nullptr, 0};
    mutable_string_view field_data{nullptr, 0};
    while (i <= cend) {
      chartype c = in[i];

      if (c == '&' || i == cend) {
        if (i == cend && !field_name_found) {

          strtype_out field_data_decoded;
          ret += percent_decode(
              strtype_in{in.data() + start, i - start},
              field_data_decoded
          );

          if (querystr) {
            out[field_data_decoded] += field_data_decoded;
          } else {
            out[reinterpret_cast<const chartype*>("")] +=
              field_data_decoded;
          }

        } else if (start < i && field_name_found) {
          strtype_out field_name_decoded;
          ret += percent_decode(
              strtype_in{field_name.p, field_name.n},
              field_name_decoded
          );

          field_data.n = i - field_data.n;

          strtype_out field_data_decoded;
          ret += percent_decode(
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
          field_data.n = i + 1;
        }
      }
      ++i;
    }

    return ret;
  }

};

#endif /* _HERMES_H_ */
