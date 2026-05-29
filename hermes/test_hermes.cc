#include <iostream>
#include <utility>
#include <cstring>
#include <cassert>
#include <hermes.hpp>
#include <testftw.hpp>

using namespace hermes;
using namespace testftw;

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
          switch (i) {
            case 0:
              assert(
                  numbers[i].first == 11 &&
                  numbers[i].second == 2 &&
                  pow(numbers[i].first, numbers[i].second) == 121
              );
              break;
            case 1:
              assert(
                  numbers[i].first == -1 &&
                  numbers[i].second == 3 &&
                  pow(numbers[i].first, numbers[i].second) == -1
              );
              break;
            case 2:
              assert(
                  numbers[i].first == 3 &&
                  numbers[i].second == 0 &&
                  pow(numbers[i].first, numbers[i].second) == 1
              );
              break;
            default:
              ;
          }
        }

        return 0;
      }, std::placeholders::_1, nnumbers));

  std::cout << "hermes::pow test start" << std::endl;
  powtest.run(numbers);
  std::cout << "hermes::pow test end" << std::endl;

  std::string querystr[] = {
    "foo%20bar=%41%42%43",
    "apples=red&oranges%20are=orange",
    "This%20is%20a%20fine%20day"
  };

  std::size_t querystrlen = sizeof(querystr)/sizeof(std::string);

  std::cout << "hermes::url::decode test start" << std::endl;

  testcase<>([querystr, querystrlen](void *dataptr, ...) {
        for (auto i = 0; i < querystrlen; ++i) {
          std::unordered_map<std::string, std::string> out;

          url::decode<char>(querystr[i], out);

          auto pidx = 0;
          for (auto &pair : out) {
            switch (i) {
              case 0:
                  assert(
                      !pair.first.compare("foo bar") &&
                      !pair.second.compare("ABC")
                  );
                  break;
              case 1:
                switch (pidx++) {
                  case 0:
                    assert(
                        !pair.first.compare("oranges are") &&
                        !pair.second.compare("orange")
                    );
                    break;
                  case 1:
                    assert(
                        !pair.first.compare("apples") &&
                        !pair.second.compare("red")
                    );
                    break;
                  default:
                    ;
                }
                break;
              case 2:
                assert(
                    !pair.first.compare("This is a fine day") &&
                    !pair.second.compare("This is a fine day")
                );
                break;
              default:
                ;
            }
          }
        }

        return 0;
      })(nullptr);

  std::cout << "hermes::url::decode test end" << std::endl;

  class encode_fixture : public fixture_base<std::string*, void*> {

    std::string rawstr[3] = {
      "foo bar=A+B",
      "oranges are=orange",
      "This is a fine day"
    };

    public:
    std::string* setup(void*) override {
      std::cout << "percent::ecnode fixture setup\n";
      return nullptr;
    }

    std::string* operator()(void*) override {
      static int i = 0;
      return i < (sizeof(rawstr) / sizeof(std::string)) ? &rawstr[i++] : nullptr;
    }

    std::string* teardown(void*) override {
      std::cout << "percent::ecnode fixture teardown\n";
      return nullptr;
    }
  } encode_fixture_obj;

  testcase<true> encode_test(
      [](
          void *dataptr,
          std::vector<fixture_interface*> fixtures
      ) {
        auto i = 0;
        while (true) {

          std::string out;
#if __cplusplus < 201703L
          auto fixture_ret =
            fixture_base<std::string*, void*>::retval(
              fixtures[0]->call(
                  fixture_base<std::string*, void*>::makearg(nullptr)
              )
            );
          if (!fixture_ret->value) {
            break;
          }
          percent::encode<>(*(fixture_ret->value), out);
#else
          auto fixture_ret =
            std::any_cast<std::string*>(
              fixtures[0]->call(nullptr)
            );
          if (!fixture_ret) {
            break;
          }
          percent::encode<>(*fixture_ret, out);
#endif

          switch (i++) {
            case 0:
              assert(out == "foo%20bar%3DA%2BB");
              break;
            case 1:
              assert(out == "oranges%20are%3Dorange");
              break;
            case 2:
              assert(out == "This%20is%20a%20fine%20day");
              break;
            default:
              ;
          }
        }

        return 0;
    },
    {
      testcase<true>::fixture_pack{
        &encode_fixture_obj,
#if __cplusplus < 201703L
        fixture_base<std::string*, void*>::makearg(nullptr)
#else
        nullptr
#endif
      }
    }
  );

  std::cout << "hermes::percent::encode test start" << std::endl;
  std::chrono::nanoseconds ns(0);
  encode_test.run(nullptr, &ns);
  std::cout << "hermes::percent::encode test took "
    << ns.count() << " nanoseconds\n";

  return 0;
}
