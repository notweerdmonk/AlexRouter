#include <iostream>
#include <utility>
#include <cstring>
#include <hermes.hpp>
#include <../../testftw/testftw.hpp>

using namespace hermes;

int main(int argc, char *argv[]) {

  std::pair<int, int> numbers[] = {
    { 11, 2 },
    { -1, 3 },
    { 3, 0 }
  };

  std::size_t nnumbers = sizeof(numbers) / sizeof(std::pair<int, int>);

  testcase<> powtest(std::bind([](void *dataptr, std::size_t nnumbers) {
        std::pair<int, int> *numbers =
          reinterpret_cast<std::pair<int, int>*>(dataptr);

        for (auto i = 0; i < nnumbers; ++i) {
          std::cout << "number: " << numbers[i].first << " exponent: "
            << numbers[i].second << " result: "
            << pow(numbers[i].first, numbers[i].second) << '\n';
        }

        return 0;
      }, std::placeholders::_1, nnumbers));

  powtest.run(numbers);

  std::string querystr[] = {
    "foo%20bar=%41%42%43",
    "apples=red&oranges%20are=orange",
    "This%20is%20a%20fine%20day"
  };

  std::size_t querystrlen = sizeof(querystr)/sizeof(std::string);

  testcase<>([querystr, querystrlen](void *dataptr) {
        for (auto i = 0; i < querystrlen; ++i) {
          std::unordered_map<std::string, std::string> out;

          url::decode<char>(querystr[i], out);

          for (auto &pair : out) {
            std::cout << pair.first << ":" << pair.second << '\n';
            //free(pair.first);
            //free(pair.second);
          }
        }

        return 0;
      })(nullptr);

  std::string rawstr[] = {
    "foo bar=A+B",
    "oranges are=orange",
    "This is a fine day"
  };

  std::size_t rawstrlen = sizeof(rawstr)/sizeof(std::string);

  class myfixture : public fixture_base<void*> {

    public:
    void setup(void *dataptr) override {
      std::cout << "setup\n";
    }

    void teardown(void *dataptr) override {
      std::cout << "teardown\n";
    }
  } myfixtureobj;

  testcase<true> encode_test(std::bind([](void *dataptr, std::size_t n) {
        std::string *str = reinterpret_cast<std::string*>(dataptr);

        for (auto i = 0; i < n; ++i) {
          std::string out;
          //char *out;

          percent::encode<>(str[i], out);

          std::cout << out << '\n';

          //free(out);
        }

        return 0;
      }, std::placeholders::_1, rawstrlen), {&myfixtureobj});

  std::chrono::nanoseconds ns(0);
  encode_test.run(rawstr, &ns);
  std::cout << "percent::encode test took " << ns.count() << " nanoseconds\n";

  return 0;
}
