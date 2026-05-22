#include <iostream>
#include <cassert>
#include <hermes.hpp>

using namespace hermes;

int main() {
  std::string str1 = "This%20is%20a%20fine%20day";
  std::string str2 = "This is a fine day";

  std::string decoded;

  percent::decode(str1, decoded);

  assert(decoded == str2);
  std::cout << decoded << '\n';

#if __cplusplus > 201402L
  array<int, 10> myarr({ 1, 3, 4, 8, 6, 5, 7, 2, ' ', '/' });
#else
  array<int, 10> myarr(std::array<int, 8>{ 1, 3, 4, 8, 6, 5, 7, 2, ' ', '/' });
#endif

  assert(myarr.contains(9) == 0);
  assert(myarr.contains(6) == 1);
  assert(myarr.contains(' ') == 1);
  assert(myarr.contains('/') == 1);

  std::string encoded;

  percent::encode(str2, encoded);

  assert(encoded == str1);
  std::cout << encoded << '\n';

  return 0;
}
