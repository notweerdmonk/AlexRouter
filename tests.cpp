#include <iostream>
#include <cassert>
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

int test_routes() {
    struct user_data {
        int test_count = 0;
        int pass_count = 0;

        std::function<
            int (
                std::vector<string_view> &args,
                std::unordered_map<std::string, std::string> &qargs
            )
        > checker;

        int do_check(
                std::vector<string_view> &args,
                std::unordered_map<std::string, std::string> &qargs
        ) {
            ++test_count;
            if (!checker(args, qargs)) {
                ++pass_count;
                return 0;
            }
            return -1;
        }
    } userdata;

    http_router<user_data*> router;

    using argstype = http_router<user_data*>::argstype;
    using qargstype = http_router<user_data*>::qargstype;

    // set up a few routes
    router.add(std::string("GET"), "/service/candy/:kind",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                            args[0] == "lollipop" ||
                            args[0] == "gum" ||
                            args[0] == "seg_råtta" ||
                            args[0] == "lakrits"
                    )) {
                        return -1;
                    }
                    if (
                            !(
                                qargs.size() == 1 &&
                                qargs["ABCD"] == "ABCD"
                            ) &&
                            !(
                                qargs.size() == 2 &&
                                qargs["foo"] == "bar" &&
                                qargs["page"] == "123"
                            ) &&
                            !(
                                qargs.size() == 0
                            )
                    ) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add(std::string("GET"), "/service/shutdown",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (
                            !(
                                args.size() == 0
                            ) &&
                            !(
                                qargs.size() == 1 &&
                                qargs["a"] == "b"
                            ) &&
                            !(
                                qargs.size() == 0
                            )
                    ) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                            args.size() == 0 &&
                            qargs.size() == 0
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/:filename",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                            args.size() == 1 &&
                            (
                                args[0] == "some_file.html" ||
                                args[0] == "another_file.jpeg"
                            )
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/:page/:username",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                            args.size() == 2 &&
                            args[0] == "1" &&
                            args[1] == "admin" &&
                            qargs.size() == 0
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/service/:kind/dash/:type",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (
                            !(
                                args.size() == 2 &&
                                args[0] == "cheese" &&
                                args[1] == "mozarella"
                            ) &&
                            !(
                                qargs.size() == 0 ||
                                (
                                    qargs.size() == 1 &&
                                    qargs["input string"] == "1 20"
                                )
                            )
                    ) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/service/:name",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                        args.size() == 1 &&
                        args[0] == "unknown" &&
                        qargs.size() == 0
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/service/:name/query/:querystr",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                        args.size() == 2 &&
                        args[0] == "cheese" &&
                        args[1] == "name" &&
                        qargs.size() == 0
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/service/*/logs",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (
                            !(
                                args.size() == 1 &&
                                (
                                    args[0] == "mail" ||
                                    args[0] == "upkeep"
                                )
                            ) &&
                            !(
                                qargs.size() == 0 ||
                                (
                                    qargs.size() == 1 &&
                                    qargs["time"] == "1732666926"
                                )
                            )
                    ) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/foo/bar/:arg/baz",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                        args.size() == 1 &&
                        args[0] == "111" &&
                        qargs.size() == 0
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    router.add("GET", "/foo/bar/:arg",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                        args.size() == 1 &&
                        args[0] == "222" &&
                        qargs.size() == 0
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    /* Should be of lower priority */
    router.add("GET", "/:name/known",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                            args.size() == 1 &&
                            args[0].size() > 0 &&
                            qargs.size() == 0
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
            }
        );

    /* Should be of higher priority becuase there is match before variable */
    router.add("GET", "/someplace/:name",
            [](user_data *user, argstype &args, qargstype &qargs) {
                assert((user && "data pointer is nullptr"));
                user->checker = [](argstype &args, qargstype &qargs) {
                    if (!(
                        args.size() == 1 &&
                        args[0] == "known" &&
                        qargs.size() == 0
                    )) {
                        return -1;
                    }
                    return 0;
                };
                if (!user->do_check(args, qargs)) {
                    std::cout << "PASS\n";
                } else {
                    std::cout << "FAIL\n";
                }
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
        router.route("GET", 3, test_url.data(), test_url.length(), &userdata);
        std::cout << std::endl;
    }

    std::cout << "=== Summary ===\n\n"
        << "Total tests:\t" << userdata.test_count << "\n"
        << "Tests passed:\t" << userdata.pass_count << "\n\n";

    return userdata.test_count == userdata.pass_count ? 0 : -1;
}

int main(int argc, char *argv[]) {
    int ret = 0;
    if (
            argc == 1 ||
            (
                argc > 1 &&
                (
                    !strncmp(argv[argc - 1], "--demo", sizeof("--demo") - 1) ||
                    !strncmp(argv[argc - 1], "-d", sizeof("-d") - 1)
                )
            )
    ) {
        calculate_cpu_clock_speed();
        std::cout << "\nDemo commences\n\n";
        demo_routes();
        std::cout << "Demo concludes\n\n";
    } else if (argc > 1) {
        if (
                !strncmp(argv[argc - 1], "--test", sizeof("--test") - 1) ||
                !strncmp(argv[argc - 1], "-t", sizeof("-t") - 1)
        ) {
            std::cout << "\nTest commences\n\n";
            ret = test_routes();
            std::cout << "Test concludes\n\n";
        } else if (
                !strncmp(argv[argc - 1], "--benchmark", sizeof("--benchmark") - 1) ||
                !strncmp(argv[argc - 1], "-b", sizeof("-b") - 1)
        ) {
            std::cout << "\nBenchmark commences\n\n";
            benchmark_routes();
            std::cout << "\nBenchmark concludes\n\n";
        } else {
            std::cout << "Invalid arguments\n";
            return -1;
        }
    }

    return ret;
}
