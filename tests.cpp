#include <iostream>
#include <chrono>

#include <HttpRouter.hpp>

static
inline
uint64_t rdtsc() {
    uint32_t lo, hi;
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

static
void calculate_cpu_clock_speed() {
    uint64_t start, end;
    std::chrono::duration<double> elapsed;

    // Get TSC and time at start
    start = rdtsc();
    auto start_time = std::chrono::high_resolution_clock::now();

    // Busy-wait loop (~1 ms)
    do {
      auto end_time = std::chrono::high_resolution_clock::now();
      elapsed = end_time - start_time;
    } while (elapsed.count() < 0.001);

    end = rdtsc();

    double fcpu_hz = (end - start) / elapsed.count();
    double fcpu_ghz = fcpu_hz / 1e9;

    std::cout << "CPU freq: " << fcpu_ghz << " GHz\n";
}

void benchmark_routes() {
    struct user_data {
        int routed = 0;
    } userData;

    http_router<user_data *> r;

    using argstype = http_router<user_data*>::argstype;
    using qargstype = http_router<user_data*>::qargstype;

    // set up a few routes
    r.add("GET", "/service/candy/:kind",
            [](user_data *user, argstype &args, qargstype &qargs) {
                user->routed++;
            }
        );

    r.add("GET", "/service/shutdown",
            [](user_data *user, argstype &args, qargstype &qargs) {
                user->routed++;
            }
        );

    r.add("GET", "/",
            [](user_data *user, argstype &args, qargstype &qargs) {
                user->routed++;
            }
        );

    r.add("GET", "/:filename",
            [](user_data *user, argstype &args, qargstype &qargs) {
                user->routed++;
            }
        );

    // run benchmark of various urls
    std::vector<std::string> test_urls = {
        "/service/candy/lollipop",
        "/service/candy/gum",
        "/service/candy/seg_råtta",
        "/service/candy/lakrits",

        "/service/shutdown",
        "/",
        "/some_file.html",
        "/another_file.jpeg"
    };

    for (std::string &test_url : test_urls) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 10000000; i++) {
            r.route("GET", 3, test_url.data(), test_url.length(), &userData);
        }
        auto stop = std::chrono::high_resolution_clock::now();
        unsigned int ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                    stop - start
            ).count();
        std::cout << "[" << 10000.0 / ms << " million req/sec] for URL: "
            << test_url << std::endl;
    }

    std::cout << "Checksum: " << userData.routed << std::endl << std::endl;
}

void demo_routes() {
    struct user_data {
        // pass whatever you need as user data
    } userData;

    http_router<user_data *> r;

    using argstype = http_router<user_data*>::argstype;
    using qargstype = http_router<user_data*>::qargstype;

    // set up a few routes
    r.add(std::string("GET"), "/service/candy/:kind",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving candy of kind " << args[0]
                    << std::endl;
                if (qargs.size()) {
                    std::cout << "query args:\n";
                }
                for (auto &qarg : qargs) {
                    std::cout << qarg.first << ":" << qarg.second << '\n';
                }
            }
        );

    r.add(std::string("GET"), "/service/shutdown",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Shutting down now" << std::endl;
                if (qargs.size()) {
                    std::cout << "query args:\n";
                }
                for (auto &qarg : qargs) {
                    std::cout << qarg.first << ":" << qarg.second << '\n';
                }
            }
        );

    r.add("GET", "/",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving index now" << std::endl;
            }
        );

    r.add("GET", "/:filename",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving file " << args[0] << std::endl;
            }
        );

    r.add("GET", "/:page/:username",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving page " << args[0] << " for username "
                    << args[1] << std::endl;
            }
        );

    r.add("GET", "/service/:kind/dash/:type",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving service of kind " << args[0] << " and type "
                    << args[1] << std::endl;
                if (qargs.size()) {
                    std::cout << "query args:\n";
                }
                for (auto &qarg : qargs) {
                    std::cout << qarg.first << ":" << qarg.second << '\n';
                }
            }
        );

    r.add("GET", "/service/:name",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving service "
                << args[0] << std::endl;
            }
        );

    r.add("GET", "/service/:name/query/:querystr",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving sevice " << args[0]
                << " query: " << args[1] << std::endl;
            }
        );

    r.add("GET", "/service/*/logs",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving logs for " << args[0]
                << std::endl;
                if (qargs.size()) {
                    std::cout << "query args:\n";
                }
                for (auto &qarg : qargs) {
                    std::cout << qarg.first << ":" << qarg.second << '\n';
                }
            }
        );

    r.add("GET", "/foo/bar/:arg/baz",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving foo/bar with baz, arg is "
                << args[0] << std::endl;
            }
        );

    r.add("GET", "/foo/bar/:arg",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Serving foo/bar, arg is "
                << args[0] << std::endl;
            }
        );

    /* Should be of lower priority */
    r.add("GET", "/:name/known",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Known place name " << args[0] << std::endl;
            }
        );

    /* Should be of higher priority becuase there is match before variable */
    r.add("GET", "/someplace/:name",
            [](user_data *user, argstype &args, qargstype &qargs) {
                std::cout << "Some place name " <<
                args[0] << std::endl;
            }
        );

    // run benchmark of various urls
    std::vector<std::string> test_urls = {
        "/service/candy/lollipop",
        "/service/candy/gum",
        "/service/candy/seg_råtta",
        "/service/candy/lakrits",

        "/service/shutdown",
        "/",
        "/some_file.html",
        "/another_file.jpeg",

        "/1/admin/",
        "/service/cheese/dash/mozarella",
        "/service/cheese/query/name/",
        "/service/mail/logs",
        "/service/mail/logs/?time=1732666926",
        "/service/upkeep/logs/?time=1732666926",
        "/foo/bar/111/baz",
        "/foo/bar/222",
        "/service/unknown",
        "/someplace/somewhere/unknown",
        "/someplace/known",
        "/service/candy/lollipop/?foo=bar&page=123",
        "/service/cheese/dash/mozarella/?=&input%20string=1%2020",
        "/service/shutdown?a=b",
        "/service/candy/gum?%41%42%43%44",
    };

    for (std::string &test_url : test_urls) {
        std::cout << "URL: [" << test_url << "]" << std::endl;
        r.route("GET", 3, test_url.data(), test_url.length(), &userData);
        std::cout << std::endl;
    }
}

int main(int argc, char *argv[]) {
    calculate_cpu_clock_speed();
    if (argc == 1) {
        std::cout << "\nDemo commences\n\n";
        demo_routes();
        std::cout << "Demo concludes\n\n";
    } else if (argc > 1) {
        std::cout << "\nBenchmark\n\n";
        benchmark_routes();
    }

    return 0;
}
