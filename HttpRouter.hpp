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

// placeholder
struct string_view {
    const char *data;
    std::size_t length;
};

std::ostream &operator<<(std::ostream &os, string_view &s) {
    os << std::string(s.data, s.length);
    return os;
}

template <typename userdata>
class http_router {
private:
    std::vector<std::function<void(userdata, std::vector<string_view> &)>> handlers;
    std::vector<string_view> params;

    using frame_type = struct {
        const char *segptr;
        const char *nodeptr;
        std::size_t params_idx;
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

    enum priority_weight {
        wildcard_weight = 1,
        variable_weight = 3,
        match_weight = 9
    };

    enum compiled_node_offset {
        node_length_offset = 0,
        node_name_length_offset = 2,
        handler_offset = 4,
        priority_offset = 6,
        abs_priority_offset = 8,
        terminal_offset = 10,
        name_offset = 11
    };

    struct node {
        using map_type = std::unordered_map<std::string, node*>;

        map_type children;
        const string_view name;
        short handler;
        unsigned short priority;
        unsigned short abs_priority;
        bool terminal;

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
            const std::string namestr(name_.data, name_.length);

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

    node *tree = new node("");
    std::string compiled_tree;
    stack_type s;

    static
    inline unsigned short node_length(const char *node) {
        return *(unsigned short *)node;
    }

    static
    inline unsigned short node_name_length(const char *node) {
        return *(unsigned short *)&node[node_name_length_offset];
    }

    static
    inline short node_handler(const char *node) {
        return *(short *)&node[handler_offset];
    }

    static
    inline unsigned short node_priority(const char *node) {
        return *(unsigned short *)&node[priority_offset];
    }

    static
    inline unsigned short node_abs_priority(const char *node) {
        return *(unsigned short *)&node[abs_priority_offset];
    }

    static
    inline bool is_terminal(const char *node) {
        return *(bool *)&node[terminal_offset];
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
        switch (segment.data[0]) {
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
        unsigned short node_len = name_offset + n->name.length;
        for (auto c : n->children) {
            node_len += compile_tree(c.second);
        }

        unsigned short node_name_len = n->name.length;

        std::string compiled_node;
        compiled_node.append((char *) &node_len, sizeof(node_len));
        compiled_node.append((char *) &node_name_len, sizeof(node_name_len));
        compiled_node.append((char *) &n->handler, sizeof(n->handler));
        compiled_node.append((char *) &n->priority, sizeof(n->priority));
        compiled_node.append((char *) &n->abs_priority, sizeof(n->abs_priority));
        compiled_node.append((char *) &n->terminal, sizeof(n->terminal));
        compiled_node.append(n->name.data, n->name.length);

        compiled_tree = compiled_node + compiled_tree;
        return node_len;
    }

    inline bool match_node(const char *candidate, const char *name,
            std::size_t name_length, std::size_t &params_idx) {

        // wildcard, parameter, equal
        if (candidate[name_offset] == '*') {
            /* use '*' for wildcards */

            return true;

        } else if (candidate[name_offset] == ':') {
            // parameter

            if (params_idx < params.size()) {
                /*
                 * Update params array at params_idx instead of appending
                 * We will always backtrack to the params_idx corresponding to
                 * current URL segment
                 */
                params[params_idx++] = string_view({name, name_length});

            } else {
                // todo: push this pointer on the stack of args!
                params.push_back(string_view({name, name_length}));

                /* maintain index of params to backtrack */
                params_idx = params.size();
            }

            return true;

        } else if (node_name_length(candidate) == name_length &&
                !memcmp(candidate + name_offset, name, name_length)) {
            return true;
        }

        return false;
    }

#if 0
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
                params.push_back(string_view({name, name_length}));

                return candidate;
            } else if (nodeNameLength == name_length && !memcmp(candidate + 6, name, name_length)) {
                return candidate;
            }

            candidate = candidate + nodeLength;
        }

        return nullptr;
    }
#endif

    // returns next slash from start or end
    inline const char *next_segment(const char *start, const char *end,
            char delimiter = '/') {
        const char *stop = (const char *) memchr(start, delimiter, end - start);
        return stop ? stop : end;
    }

    inline void push_children(const char *segment, const char *node,
            std::size_t params_idx) {

        for (const char *child = node + name_offset + node_name_length(node);
                child < node + node_length(node);
                child = child + node_length(child)) {

            s.push({segment, child, params_idx});
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
    inline std::make_signed_t<std::size_t> lookup(const char *url, int length) {

        const char *found = nullptr;

        const char *compiled_node = (char *) compiled_tree.data();
        const char *stop, *start = url;
        const char *end_ptr = next_segment(url, url + length, '?');

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

            if (!match_node(compiled_node, start, stop - start, frame.params_idx)) {
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
            push_children(start, compiled_node, frame.params_idx);
        }

#if 0
        do {
            stop = next_segment(start, end_ptr);

            //std::cout << "Matching(" << std::string(start, stop - start) << ")" << std::endl;

            if(nullptr == (compiled_node = find_node(compiled_node, start, stop - start))) {
                return -1;
            }

            start = stop + 1;
        } while (stop != end_ptr);
#endif

        return found ? node_handler(found) : -1;
    }

public:
    http_router() {
        // maximum 100 parameters
        params.reserve(100);
    }

    ~http_router() {
        free_children(tree);
    }
        
    void add(const char *method, const char *pattern,
            std::function<void(userdata, std::vector<string_view>&)> handler) {

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

            nodes.push_back({start,
                    static_cast<decltype(string_view::length)>(stop - start)});

            start = stop + 1;
        } while (stop != end_ptr && start != end_ptr);

        add_nodes(nodes, handlers.size());
        handlers.push_back(handler);

        compile();
    }

    void add(const std::string &method, const std::string &pattern,
            std::function<void(userdata, std::vector<string_view>&)> handler) {

        add(method.c_str(), pattern.c_str(), handler);
    }

    void compile() {
        compiled_tree.clear();
        compile_tree(tree);
    }

    void route(const char *method, unsigned int method_length, const char *url,
            unsigned int url_length, userdata userData) {

        using size_type = decltype(handlers)::size_type;

        /* Prepend method to URL */
        char target[method_length + url_length + 1];
        memcpy(target, method, method_length);
        memcpy(target + method_length, url, url_length);
        target[method_length + url_length] = '\0';

        auto handler_id = lookup(target, method_length + url_length);
        if (handler_id > -1 &&
                static_cast<size_type>(handler_id) < handlers.size()) {
            handlers[handler_id](userData, params);
            params.clear();
        }
    }
};

#endif // HTTPROUTER_HPP
