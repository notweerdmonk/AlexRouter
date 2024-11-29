# HttpRouter
Simple & fast header-only router for HTTP servers.

* Patterns with wildcards and parameters.
* Functional handlers
* Cross-platform
* SIMD/zero-copy parsing
* No memory allocations

```c++
    struct UserData {
        // pass whatever you need as user data
    } userData;

    HttpRouter<UserData *> r;

    r.add("GET", "/service/candy/:kind", [](UserData *user, auto &args) {
        std::cout << "Now serving candy of kind " << args[0] << std::endl;
    });

    r.add("GET", "/service/shutdown", [](UserData *user, auto &args) {
        std::cout << "Shutting down now" << std::endl;
    });

    r.route("GET", 3, "/service/candy/lollipop", 23, &userData);
```
