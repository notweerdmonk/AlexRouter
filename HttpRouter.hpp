#ifndef HTTPROUTER_HPP
#define HTTPROUTER_HPP

#include <map>
#include <functional>
#include <vector>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <climits>
#include <type_traits>
#include <unordered_map>
#include <hermes.hpp>

#if defined(__GNUC__)
#define __inline [[gnu::always_inline]]
#elif defined(__clang__)
#define __inline [[clang::always_inline]]
#elif defined(_MSC_VER)
#define __inline [[msvc::forceinline]]
#else
#define __inline inline
#endif

#if __cplusplus < 201703L

#define IF_CONSTEXPR if

#else /* __cplusplus < 201703L */

#define IF_CONSTEXPR if constexpr

#endif /* __cplusplus < 201703L */

#if __cplusplus < 201703L

struct string_view {

    using size_type = std::size_t;

    const char *data_;
    size_type length_;

    string_view() : data_(nullptr), length_(0) {
    }

    string_view(const char *data, size_type length)
        : data_(data), length_(length) {
    }

    string_view(const char *data)
        : data_(data), length_(std::strlen(data)) {
    }

    __inline
    const char* data() const {
        return data_;
    }

    __inline
    size_type length() const {
        return length_;
    }

    __inline
    size_type size() const {
        return length_;
    }

#if __cplusplus > 201103L
    constexpr
#endif
    void remove_prefix(size_type n) {
        data_ += n;
        length_ -= n;
    }

#if __cplusplus > 201103L
    constexpr
#endif
    void remove_suffix(size_type n) {
        length_ -= n;
    }

    char operator[](size_type i) const {
        return data_[i];
    }

    bool operator==(const string_view &other) {
        return length_ == other.length_ &&
            std::memcmp(data_, other.data_, length_) == 0;
    }

    bool operator==(string_view &&other) {
        return length_ == other.length_ &&
            std::memcmp(data_, other.data_, length_) == 0;
    }

    class const_iterator {
        const char *pdata;

        friend
        struct string_view;

        friend
        const_iterator operator+(int n, const const_iterator &it);

        friend
        const_iterator operator+(int n, string_view::const_iterator &&it);

    public:
        const_iterator() : pdata(nullptr) {
        }

        const_iterator(const char* pdata_) : pdata(pdata_) {
        }

        const_iterator(const const_iterator &other) : pdata(other.pdata) {
        }

        const_iterator(const_iterator &&other) : pdata(other.pdata) {
        }

        const_iterator& operator=(const const_iterator &other) {
            pdata = other.pdata;
            return *this;
        }

        const_iterator& operator=(const_iterator &&other) {
            pdata = other.pdata;
            return *this;
        }

        char operator*() const {
            return *pdata;
        }

        const_iterator operator++() {
            const_iterator copy = *this;
            ++pdata;
            return copy;
        }

        const_iterator& operator++(int n) {
            ++pdata;
            return *this;
        }

        bool operator==(const const_iterator &other) {
            return pdata == other.pdata;
        }

        bool operator!=(const const_iterator &other) {
            return pdata != other.pdata;
        }

        bool operator<(const const_iterator &other) {
            return pdata < other.pdata;
        }

        bool operator<=(const const_iterator &other) {
            return pdata <= other.pdata;
        }

        bool operator>(const const_iterator &other) {
            return pdata > other.pdata;
        }

        bool operator>=(const const_iterator &other) {
            return pdata >= other.pdata;
        }

        const_iterator operator+(int n) {
            return const_iterator(pdata + n);
        }

        const_iterator operator+(unsigned int n) {
            return const_iterator(pdata + n);
        }

        const_iterator operator+(std::size_t n) {
            return const_iterator(pdata + n);
        }

        size_type operator-(const const_iterator &other) const {
            return pdata - other.pdata;
        }

        const_iterator operator-(int n) {
            return const_iterator(pdata - n);
        }

        const_iterator operator-(unsigned int n) {
            return const_iterator(pdata - n);
        }

        const_iterator operator-(std::size_t n) {
            return const_iterator(pdata - n);
        }

        const_iterator operator+=(int n) {
            pdata += n;
            return *this;
        }

        const_iterator operator+=(unsigned int n) {
            pdata += n;
            return *this;
        }

        const_iterator operator+=(std::size_t n) {
            pdata += n;
            return *this;
        }

        const_iterator operator-=(int n) {
            pdata -= n;
            return *this;
        }

        const_iterator operator-=(unsigned int n) {
            pdata -= n;
            return *this;
        }

        const_iterator operator-=(std::size_t n) {
            pdata -= n;
            return *this;
        }
    };

    string_view(const const_iterator &cbegin, const const_iterator &cend)
        : data_(cbegin.pdata), length_(cend - cbegin) {
    }

    string_view(const const_iterator &cbegin, size_type length)
        : data_(cbegin.pdata), length_(length) {
    }

    const_iterator cbegin() const {
        return const_iterator(data_);
    }

    const_iterator cend() const {
        return const_iterator(data_ + length_);
    }
};

struct string_view_hash {
  std::size_t operator()(const string_view& sv) const {
      /* Hash the string */
      std::size_t h1 = std::hash<const char*>{}(sv.data());
      /* Hash the size */
      std::size_t h2 = std::hash<std::size_t>{}(sv.length());

      /* Combine the two hashes: XOR and multiply by a prime number */
      return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
  }
};

string_view::const_iterator operator+(int n,
        const string_view::const_iterator &it) {
    return string_view::const_iterator(it.pdata + n);
}

string_view::const_iterator operator+(int n, string_view::const_iterator &&it) {
    return string_view::const_iterator(it.pdata + n);
}

std::ostream& operator<<(std::ostream &os, const string_view &s) {
    return os << std::string(s.data(), s.length());
}

#else /* __cplusplus < 201703L */

using std::string_view;

#endif /* __cplusplus < 201703L */

template <typename userdata>
class http_router {

public:
    using argstype = std::vector<string_view>;
    using qargstype = std::unordered_map<std::string, std::string>;
    using handlertype = std::function<void(userdata, argstype&, qargstype&)>;

private:
    std::vector<handlertype> handlers;
    argstype args;
    qargstype qargs;

    using frame_type = struct {
        const char *segptr;
        const char *nodeptr;
        std::size_t args_idx;
    };

    template <typename frame>
    class stack {
        frame *data_;
        std::size_t capacity_;
        std::size_t idx_;

        enum { BLOCK_SIZE = 64 };

        frame* alloc(frame *&mem, std::size_t nbytes) {
            mem = reinterpret_cast<frame*>(realloc(data_, nbytes));
            if (!mem) {
                throw std::runtime_error("Could not allocate memory");
            }
            return mem;
        }

        public:
        stack(std::size_t capacity = BLOCK_SIZE)
            : data_(nullptr), capacity_(capacity), idx_(0) {

            (void)alloc(data_, capacity_ * sizeof(frame));
        }

        ~stack() {
            free(data_);
        }

        bool empty() const {
            return idx_ == 0;
        }

        std::size_t size() const {
            return idx_;
        }

        void push(const frame &f) {
            if (idx_ == capacity_) {
                (void)alloc(data_, (capacity_ <<= 1) * sizeof(frame));
            }

            data_[idx_++] = f;
        }

        frame& top() const {
            if (empty()) {
                return frame();
            }

            return data_[idx_ - 1];
        }

        frame pop() {
            if (empty()) {
                return frame();
            }

            return data_[--idx_];
        }

        void clear() {
            idx_ = 0;
        }
    };

    using stack_type = stack<frame_type>;

    struct node {
        using map_type = std::unordered_map<std::string, node*>;
        using size_type = unsigned short;

        map_type children;
        const string_view name;
        short handler;
        unsigned short priority;
        unsigned short abs_priority;
        bool terminal;

        node(const char *nameptr)
            : name(nameptr, strlen(nameptr)), handler(-1), terminal(false) {
        }

        node(const char *nameptr, string_view::size_type namelength)
            : name(nameptr, namelength), handler(-1), terminal(false) {
        }

        node(const std::string &name_)
            : name(name_.data(), name_.size()), handler(-1), terminal(false) {
        }

        node(std::string &&name_)
            : name(name_.data(), name_.size()), handler(-1), terminal(false) {
        }

        node(const string_view &name_)
            : name(name_), handler(-1), terminal(false) {
        }

        node(string_view &&name_)
            : name(std::move(name_)), handler(-1), terminal(false) {
        }

        node* add(const string_view &name_) {
            typename map_type::iterator next;
            const std::string namestr(name_.data(), name_.length());

            if ((next = children.find(namestr)) == children.end()) {
                /*
                 * Create an entry in the map and get it.
                 * Insertion will succeed because we found no entries earlier,
                 * can skip checking second element of std::pair.
                 */
                next = children.emplace(std::make_pair(std::move(namestr),
                            nullptr)).first;

                next->second = new node(string_view(next->first.data(),
                            next->first.size()));
            }

            return next->second;
        }
    };

    enum priority_weight {
        wildcard_weight = 1,
        variable_weight = 3,
        match_weight = 9
    };

    enum compiled_node_member_sizes {
        node_length_size        = sizeof(typename node::size_type),
        node_name_length_size   = sizeof(typename node::size_type),
        handler_size            = sizeof(node::handler),
        priority_size           = sizeof(node::priority),
        abs_priority_size       = sizeof(node::abs_priority),
        terminal_size           = sizeof(node::terminal)
    };

    enum compiled_node_offset {
        node_length_offset      = 0,
        node_name_length_offset = node_length_offset + node_length_size,
        handler_offset          = node_name_length_offset + node_name_length_size,
        priority_offset         = handler_offset + handler_size,
        abs_priority_offset     = priority_offset + priority_size,
        terminal_offset         = abs_priority_offset + abs_priority_size,
        name_offset             = terminal_offset + terminal_size
    };

    node *tree = new node("");
    std::string compiled_tree;
    stack_type s;

    template<typename T>
    __inline
    static
    constexpr
    T read_node_data(const void *node, std::size_t bytes_offset = 0) {
#if __cplusplus >= 201703L
        const std::byte *byteptr = static_cast<const std::byte*>(node);
#else
        const unsigned char *byteptr = static_cast<const unsigned char*>(node);
#endif
        T tmpobj;
        std::memcpy(&tmpobj, byteptr + bytes_offset, sizeof(T));
        return tmpobj;
    }

    __inline
    static
    constexpr
    unsigned short node_length(const void *node) {
        return read_node_data<unsigned short>(node);
    }

    __inline
    static
    constexpr
    unsigned short node_name_length(const void *node) {
        return read_node_data<unsigned short>(node, node_name_length_offset);
    }

    __inline
    static
    constexpr
    short node_handler(const void *node) {
        return read_node_data<short>(node, handler_offset);
    }

    __inline
    static
    constexpr
    unsigned short node_priority(const void *node) {
        return read_node_data<unsigned short>(node, priority_offset);
    }

    __inline
    static
    constexpr
    unsigned short node_abs_priority(const void *node) {
        return read_node_data<unsigned short>(node, abs_priority_offset);
    }

    __inline
    static
    constexpr
    bool is_terminal(const void *node) {
        return read_node_data<bool>(node, terminal_offset);
    }

    void free_children(node *parent) {
        if (!parent) {
            return;
        }

        for (auto &child : parent->children) {
            free_children(child.second);
        }

        delete parent;
    }

    /* Assume string_view length > 0 because next_segment split the route */
    unsigned short segment_weight(const string_view &segment) {
        switch (segment.data()[0]) {
            case '*':
                return wildcard_weight;

            case ':':
                return variable_weight;

            default:
                return match_weight;
        }
    }

    void add_nodes(std::vector<string_view> route, short handler) {
        node *parent = tree;

        using size_type = std::vector<string_view>::size_type;

        const size_type size = route.size();
        unsigned int priority = 0;
        unsigned int abs_priority = 0;

        for (size_type i = 0; i < size; ++i) {
            const string_view &segment = route[i];
            const unsigned short weight = segment_weight(segment);

            priority += weight;
            /* Handle overflow */
            if (priority > USHRT_MAX) {
                priority = USHRT_MAX;
            }

            abs_priority += (1 << (size - i - 1)) * weight;
            /* Handle overflow */
            if (abs_priority > USHRT_MAX) {
                abs_priority = USHRT_MAX;
            }

            parent = parent->add(segment);
        }

        parent->handler = handler;
        parent->priority = priority;
        parent->abs_priority = abs_priority;
        parent->terminal = true;
    }

    unsigned short compile_tree(node *n) {
        unsigned short node_len = name_offset + n->name.length();
        for (auto c : n->children) {
            node_len += compile_tree(c.second);
        }

        unsigned short node_name_len = n->name.length();

        std::string compiled_node(
            sizeof(node_len) +
            sizeof(node_name_len) +
            sizeof(n->handler) +
            sizeof(n->priority) +
            sizeof(n->abs_priority) +
            sizeof(n->terminal) +
            static_cast<std::size_t>(node_name_len),
            '\0'
        );

        char* ptr = &compiled_node[0];

#ifdef __GNUC__

        ptr = reinterpret_cast<decltype(ptr)>(
                mempcpy(ptr, &node_len, sizeof(node_len))
        );
        ptr = reinterpret_cast<decltype(ptr)>(
            mempcpy(ptr, &node_name_len, sizeof(node_name_len))
		    );
        ptr = reinterpret_cast<decltype(ptr)>(
            mempcpy(ptr, &n->handler, sizeof(n->handler))
		    );
        ptr = reinterpret_cast<decltype(ptr)>(
            mempcpy(ptr, &n->priority, sizeof(n->priority))
		    );
        ptr = reinterpret_cast<decltype(ptr)>(
            mempcpy(ptr, &n->abs_priority, sizeof(n->abs_priority))
		    );
        ptr = reinterpret_cast<decltype(ptr)>(
            mempcpy(ptr, &n->terminal, sizeof(n->terminal))
		    );
        memcpy(ptr, n->name.data(), node_name_len);

#else

        memcpy(ptr, &node_len, sizeof(node_len));
        ptr += sizeof(node_len);
        memcpy(ptr, &node_name_len, sizeof(node_name_len));
        ptr += sizeof(node_name_len);
        memcpy(ptr, &n->handler, sizeof(n->handler));
        ptr += sizeof(n->handler);
        memcpy(ptr, &n->priority, sizeof(n->priority));
        ptr += sizeof(n->priority);
        memcpy(ptr, &n->abs_priority, sizeof(n->abs_priority));
        ptr += sizeof(n->abs_priority);
        memcpy(ptr, &n->terminal, sizeof(n->terminal));
        ptr += sizeof(n->terminal);
        memcpy(ptr, n->name.data(), node_name_len);

#endif

        compiled_tree = compiled_node + compiled_tree;
        return node_len;
    }

    static
    void query_args(
            const char* in,
            std::size_t len,
            qargstype &qargs
    ) {
        string_view target(in, len);
        hermes::query_decode<>(target, qargs);
    }

    inline bool match_node(const char *candidate, const char *name,
            std::size_t name_length, std::size_t &args_idx) {

        // wildcard, parameter, equal
        if (candidate[name_offset] == '*') {
            /* use '*' for wildcards */

            return true;

        } else if (candidate[name_offset] == ':') {
            // parameter

            if (args_idx < args.size()) {
                /*
                 * Update args array at args_idx instead of appending
                 * We will always backtrack to the args_idx corresponding to
                 * current URL segment
                 */
                args[args_idx++] = string_view({name, name_length});

            } else {
                // todo: push this pointer on the stack of args!
                args.push_back(string_view({name, name_length}));

                /* maintain index of args to backtrack */
                args_idx = args.size();
            }

            return true;

        } else if (node_name_length(candidate) == name_length &&
                !memcmp(candidate + name_offset, name, name_length)) {
            return true;
        }

        return false;
    }

    /* Deprecated */
    inline const char *find_node(const char *parent_node, const char *name,
        std::size_t name_length) {

        unsigned short nodeLength = *(unsigned short *) &parent_node[0];
        unsigned short nodeNameLength = *(unsigned short *) &parent_node[2];

        //std::cout << "Finding node: <" << std::string(name, name_length) << ">" << std::endl;

        const char *stoppp = parent_node + nodeLength;
        for (const char *candidate = parent_node + 6 + nodeNameLength; candidate < stoppp; ) {

            unsigned short nodeLength = *(unsigned short *) &candidate[0];
            unsigned short nodeNameLength = *(unsigned short *) &candidate[2];

            // whildcard, parameter, equal
            if (nodeNameLength == 0) {
                return candidate;
            } else if (candidate[6] == ':') {
                // parameter

                // todo: push this pointer on the stack of args!
                args.push_back(string_view({name, name_length}));

                return candidate;
            } else if (nodeNameLength == name_length && !memcmp(candidate + 6, name, name_length)) {
                return candidate;
            }

            candidate = candidate + nodeLength;
        }

        return nullptr;
    }

    // returns next slash from start or end
    inline const char *next_segment(const char *start, const char *end,
            char delimiter = '/') {
        const char *stop = (const char *) memchr(start, delimiter, end - start);
        return stop ? stop : end;
    }

    inline void push_children(const char *segment, const char *node,
            std::size_t args_idx) {

        for (const char *child = node + name_offset + node_name_length(node);
                child < node + node_length(node);
                child = child + node_length(child)) {

            s.push({segment, child, args_idx});
        } 
    }

    inline void store_match(const char *&store, const char *match) {
        if (!match) {
            return;
        }

        if (!store) {
            store = match;
            return;
        }

        const unsigned short store_prio = node_priority(store);
        const unsigned short match_prio = node_priority(match);

        if (store_prio > match_prio) {
            return;
        }

        if (store_prio == match_prio &&
                node_abs_priority(store) >= node_abs_priority(match)) {
            return;
        }

        store = match;
    }

    // should take method also!
    inline std::make_signed<std::size_t>::type lookup(const char *url, int length) {

        const char *found = nullptr;

        const char *compiled_node = (char *) compiled_tree.data();
        const char *stop, *start = url;
        const char *end_ptr = next_segment(url, url + length, '?');

        std::size_t remaining = length - (end_ptr - start);

        if (remaining > 0) {
            query_args(end_ptr + 1, remaining, qargs);
        }

        s.clear();

        /* Push children on to stack */
        push_children(start, compiled_node, 0);

        while (!s.empty()) {
            auto frame = s.pop();

            /* Fetch URL segment ptr */
            start = frame.segptr;

            /* Fetch trie node ptr */
            compiled_node = frame.nodeptr;

            /* Get the end of current segment */
            stop = next_segment(start, end_ptr);

            //std::cout << "Matching(" << std::string(start, stop - start) << ")"
            //    << std::endl;

            if (!match_node(compiled_node, start, stop - start, frame.args_idx)) {
                continue;
            }

            /* Move to next URL segment */
            start = stop + 1;

            /* Check if we have reached the end of URL string and trie node is
             * terminal */
            if ( (stop == end_ptr || start == end_ptr) &&
                    is_terminal(compiled_node) ) {

                store_match(found, compiled_node);
                continue;
            }
            
            /* Push children on to stack */
            push_children(start, compiled_node, frame.args_idx);
        }

        /* Deprecated */
        IF_CONSTEXPR (false) {
            do {
                stop = next_segment(start, end_ptr);

                //std::cout << "Matching(" << std::string(start, stop - start) << ")" << std::endl;

                if(nullptr == (compiled_node = find_node(compiled_node, start, stop - start))) {
                    return -1;
                }

                start = stop + 1;
            } while (stop != end_ptr);
        }

        return found ? node_handler(found) : -1;
    }

public:
    http_router() {
        // maximum 100 parameters
        args.reserve(100);
    }

    ~http_router() {
        free_children(tree);
    }
        
    void add(const char *method, const char *pattern, handlertype handler) {

        // if pattern starts with / then move 1+ and run inline slash parser

        // step over any initial slash
        if (pattern[0] == '/') {
            pattern++;
        }

        const char *stop, *start = pattern;
        const char *end_ptr =
            next_segment(pattern, pattern + strlen(pattern), '?');

        std::vector<string_view> nodes;
        nodes.push_back({method, strlen(method)});

        do {
            stop = next_segment(start, end_ptr);

            //std::cout << "Segment(" << std::string(start, stop - start) << ")" << std::endl;

            nodes.push_back(
                    {start,
                    static_cast<string_view::size_type>(stop - start)}
            );

            start = stop + 1;
        } while (stop != end_ptr && start != end_ptr);

        add_nodes(nodes, handlers.size());
        handlers.push_back(handler);

        compile();
    }

    void add(const std::string &method, const std::string &pattern,
            handlertype handler) {

        add(method.c_str(), pattern.c_str(), handler);
    }

    void compile() {
        compiled_tree.clear();
        compile_tree(tree);
    }

    void route(const char *method, unsigned int method_length, const char *url,
            unsigned int url_length, userdata userData) {

        using size_type = typename decltype(handlers)::size_type;

        /* Prepend method to URL */
        char target[method_length + url_length + 1];
        memcpy(target, method, method_length);
        memcpy(target + method_length, url, url_length);
        target[method_length + url_length] = '\0';

        auto handler_id = lookup(target, method_length + url_length);
        if (
                handler_id > -1 &&
                static_cast<size_type>(handler_id) < handlers.size()
        ) {
            handlers[handler_id](userData, args, qargs);
            args.clear();
            qargs.clear();
        }
    }
};

#endif // HTTPROUTER_HPP
