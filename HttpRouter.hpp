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
#include <algorithm>
#include <memory>
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

#if __cplusplus < 201402L

namespace std {
    namespace detail {

        template<typename>
        struct is_unbounded_array {
            static constexpr bool value = false;
        };

        template<typename T>
        struct is_unbounded_array<T[]> {
            static constexpr bool value = true;
        };

        template<typename>
        struct is_bounded_array {
            static constexpr bool value = false;
        };

        template<typename T, std::size_t N>
        struct is_bounded_array<T[N]> {
            static constexpr bool value = true;
        };

    }; /* namespace detail */

    template<
        typename T,
        class... Args
    >
    typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T>>::type
    make_unique(Args&&... args) {
        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    }

    template<
        typename T
    >
    typename std::enable_if<
        detail::is_unbounded_array<T>::value,
        std::unique_ptr<T>
    >::type
    make_unique(std::size_t n) {
        return std::unique_ptr<T>(new T(std::remove_extent<T>::type[n]()));
    }

    template<
        typename T,
        class... Args
    >
    typename std::enable_if<
        detail::is_bounded_array<T>::value,
        std::unique_ptr<T>
    >::type
    make_unique(Args&&... args) = delete;

}; /* namespace std */

#endif /* __cplusplus < 201402L */

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
    template <typename frame>
    class stack {
        frame *data_;
        std::size_t capacity_;
        std::size_t idx_;

        enum { BLOCK_SIZE = 64 };

        frame* alloc(frame *&mem, std::size_t nbytes) {
            mem = reinterpret_cast<frame*>(realloc(data_, nbytes));
            if (!mem) {
                throw std::bad_alloc();
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

        /*
         * Calling tis function when the stack is empty shall lead to undefined
         * behavior.
         */
        frame& top() const {
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

    struct node {
        using nodeptr_type = std::unique_ptr<node>;
        using map_type =
            std::unordered_map<std::string, nodeptr_type>;
        using size_type = std::size_t;

        map_type children;
        const string_view name;
        std::unique_ptr<handlertype> handler;
        unsigned short priority;
        unsigned short abs_priority;
        bool terminal;

        node(const char *nameptr)
            : node(nameptr, nullptr) {
        }

        node(const char *nameptr, string_view::size_type namelength)
            : node(nameptr, namelength, nullptr) {
        }

        node(const std::string &name)
            : node(name, nullptr) {
        }

        node(std::string &&name)
            : node(name, nullptr) {
        }

        node(const string_view &name)
            : node(name, nullptr) {
        }

        node(string_view &&name)
            : node(name, nullptr) {
        }

        node(
                const char *nameptr,
                string_view::size_type namelength,
                std::unique_ptr<handlertype>&& handler
        ) : name(nameptr, namelength), handler(std::move(handler)),
            terminal(false) {
        }

        node(
                const char *nameptr,
                std::unique_ptr<handlertype>&& handler
        ) : name(nameptr, strlen(nameptr)), handler(std::move(handler)),
            terminal(false) {
        }

        node(
                const std::string &name,
                std::unique_ptr<handlertype>&& handler
        ) : name(name.data(), name.size()), handler(std::move(handler)),
            terminal(false) {
        }

        node(
                std::string &&name,
                std::unique_ptr<handlertype>&& handler
        ) : name(name.data(), name.size()), handler(std::move(handler)),
            terminal(false) {
        }

        node(
                const string_view &name,
                std::unique_ptr<handlertype>&& handler
        ) : name(name), handler(std::move(handler)),
            terminal(false) {
        }

        node(
                string_view &&name,
                std::unique_ptr<handlertype>&& handler
        ) : name(std::move(name)), handler(std::move(handler)),
            terminal(false) {
        }

        node(
                const char *nameptr,
                string_view::size_type namelength,
                const std::unique_ptr<handlertype>& handler
        ) : name(nameptr, namelength), handler(handler),
            terminal(false) {
        }

        node(
                const char *nameptr,
                const std::unique_ptr<handlertype>& handler
        ) : name(nameptr, strlen(nameptr)), handler(handler),
            terminal(false) {
        }

        node(
                const std::string &name,
                const std::unique_ptr<handlertype>& handler
        ) : name(name.data(), name.size()), handler(handler),
            terminal(false) {
        }

        node(
                std::string &&name,
                const std::unique_ptr<handlertype>& handler
        ) : name(name.data(), name.size()), handler(handler),
            terminal(false) {
        }

        node(
                const string_view &name,
                const std::unique_ptr<handlertype>& handler
        ) : name(name), handler(handler),
            terminal(false) {
        }

        node(
                string_view &&name,
                const std::unique_ptr<handlertype>& handler
        ) : name(std::move(name)), handler(handler),
            terminal(false) {
        }

        nodeptr_type& add(const string_view &name_) {
            typename map_type::iterator next;
            const std::string namestr(name_.data(), name_.length());

            if ((next = children.find(namestr)) == children.end()) {
                /*
                 * Create an entry in the map and get it.
                 * Insertion will succeed because we found no entries earlier,
                 * can skip checking second element of std::pair.
                 */
                next = children.emplace(
                        std::make_pair(std::move(namestr), nullptr)
                ).first;

                next->second = std::make_unique<node>(
                        string_view(next->first.data(), next->first.size())
                    );
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
        handler_size            = sizeof(typename decltype(node::handler)::pointer),
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

    using compiled_tree_datatype = unsigned char;
    using compiled_tree_type = std::vector<compiled_tree_datatype>;

    using route_frame_type = struct {
        const char *segptr;
        const compiled_tree_datatype *nodeptr;
        std::size_t args_idx;
    };
    using route_stack_type = stack<route_frame_type>;

    typename node::nodeptr_type tree = std::make_unique<node>("");

    argstype args1, args2;
    qargstype qargs;
    std::reference_wrapper<argstype> route_args = args1;
    std::reference_wrapper<argstype> args = args2;

    compiled_tree_type compiled_tree;

    route_stack_type route_stack;

    template<typename T>
    __inline
    static
    constexpr
    T read_node_data(
            const void *node,
            typename node::size_type bytes_offset = 0
    ) {
#if __cplusplus >= 201703L
        const std::byte *byteptr = static_cast<const std::byte*>(node);
#else
        const compiled_tree_datatype *byteptr =
            static_cast<const compiled_tree_datatype*>(node);
#endif
        T tmpobj;
        std::memcpy(&tmpobj, byteptr + bytes_offset, sizeof(T));
        return tmpobj;
    }

    __inline
    static
    constexpr
    typename node::size_type node_length(const void *node) {
        return read_node_data<unsigned short>(node);
    }

    __inline
    static
    constexpr
    typename node::size_type node_name_length(const void *node) {
        return read_node_data<unsigned short>(node, node_name_length_offset);
    }

    __inline
    static
    constexpr
    handlertype* node_handler(const void *node) {
        return read_node_data<handlertype*>(node, handler_offset);
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

    void add_nodes(
            std::vector<string_view> route,
            std::unique_ptr<handlertype>&& handler
    ) {
        std::reference_wrapper<typename node::nodeptr_type> parent = tree;

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

            parent = parent.get()->add(segment);
        }

        parent.get()->handler = std::move(handler);
        parent.get()->priority = priority;
        parent.get()->abs_priority = abs_priority;
        parent.get()->terminal = true;
    }

    /*
     * Algorithm: PostorderDepthToLeaf(root)
     * Input: root — root of an N-ary tree (each node has .children list)
     * Output: list of pairs (node, depth) where depth = number of edges from node to deepest leaf
     * 
     * Definitions:
     *   Frame = (node, visited, max_child)
     *     node: tree node
     *     parent: tree node
     *     parent_tree_depth: integer (initially 0 to indicate "no subtree")
     *     tree_depth: integer (initially 0 to indicate "no subtree")
     *     visited: boolean
     * 
     * Procedure PostorderDepthToLeaf(root)
     * 1.  if root = NULL then
     * 2.      return empty list
     * 3.  end if
     * 4.
     * 5.  result ← empty list           // will hold pairs (node, depth)
     * 6.  stack ← empty stack of Frame
     * 7.  PUSH(stack, (root, NULL, 0, 0, FALSE))
     * 8.
     * 9.  while NOT EMPTY(stack) do
     * 10.     (node, parent, parent_tree_depth, tree_depth, visited) ← POP(stack)
     * 11.
     * 12.     if visited = FALSE then
     * 13.         if tree_depth = 0 then
     * 14.             depth ← 0          // node is a leaf
     * 15.         else
     * 16.             depth ← tree_depth + 1
     * 17.         end if
     * 18.
     * 19.         APPEND(result, (node, depth))
     * 20.
     * 21.         if NOT EMPTY(stack) then
     * 23.             (pnode, pparent, pparent_tree_depth , ptree_depth, pvisited) ← POP(stack)
     * 24.             if parent = pparent then
     * 25.                 // sibling: add current depth and depths of previous
     *                     // siblings to depth of parent
     * 25.                 pparent_tree_depth ← pparent_tree_depth + parent_tree_depth + depth
     * 26.             else if parent = pnode then
     *                     // parent: add current depth and depths of previous
     *                     // siblings to depth of parent
     * 27.                 ptree_depth = parent_tree_depth + depth
     * 28.             end if
     * 29.             PUSH(stack, (pnode, pparent, pparent_tree_depth , ptree_depth, pvisited))
     * 30.         end if
     * 31.     else
     * 32.         // first visit: schedule node for revisit after children
     * 33.         PUSH(stack, (node, TRUE, −∞))
     * 34.         // push children so they are processed before node;
     * 35.         // push in reverse order to process left-most child first
     * 36.         for i ← LENGTH(node.children) − 1 downto 0 do
     * 37.             child ← node.children[i]
     * 38.             PUSH(stack, (child, FALSE, −∞))
     * 39.         end for
     * 40.     end if
     * 41. end while
     * 42.
     * 43. return result
     * 44. End Procedure
     *
     */
    typename node::size_type compile_tree(typename node::nodeptr_type& n) {
        using node_frame_type = struct {
            node *nodeptr;
            node *parent;
            typename node::size_type parent_tree_len;
            typename node::size_type tree_len;
            bool visited;
        };
        using node_stack_type = stack<node_frame_type>;

        node_stack_type node_stack;

        typename node::size_type total_node_len = 0;

        node_stack.push({n.get(), nullptr, 0, 0, false});

        while (!node_stack.empty()) {
            auto &frame = node_stack.top();

            if (!frame.visited) {

                frame.visited = true;

                auto n = frame.nodeptr;
                for (auto &c : n->children) {
                    node_stack.push({c.second.get(), n, 0, 0, false});
                }

                continue;
            }

            frame = node_stack.pop();
            auto n = frame.nodeptr;

            typename node::size_type node_name_len = n->name.length();
            typename node::size_type node_len = name_offset + node_name_len;

            if (frame.tree_len) {
                node_len += frame.tree_len;
            }

            compiled_tree_type compiled_node(
                sizeof(typename node::size_type) +
                sizeof(typename node::size_type) +
                sizeof(typename decltype(n->handler)::pointer) +
                sizeof(n->priority) +
                sizeof(n->abs_priority) +
                sizeof(n->terminal) +
                node_name_len,
                '\0'
            );

            compiled_tree_datatype *ptr = &compiled_node[0];
            handlertype *handler_ptr = n->handler.get();

#ifdef __GNUC__

            ptr = reinterpret_cast<decltype(ptr)>(
                    mempcpy(ptr, &node_len, sizeof(node_len))
                );
            ptr = reinterpret_cast<decltype(ptr)>(
                    mempcpy(ptr, &node_name_len, sizeof(node_name_len))
                );
            ptr = reinterpret_cast<decltype(ptr)>(
                mempcpy(
                    ptr,
                    &handler_ptr,
                    sizeof(typename decltype(n->handler)::pointer)
                )
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
            memcpy(
                ptr,
                &handler_ptr,
                sizeof(typename decltype(n->handler)::pointer)
            );
            ptr += sizeof(n->handler);
            memcpy(ptr, &n->priority, sizeof(n->priority));
            ptr += sizeof(n->priority);
            memcpy(ptr, &n->abs_priority, sizeof(n->abs_priority));
            ptr += sizeof(n->abs_priority);
            memcpy(ptr, &n->terminal, sizeof(n->terminal));
            ptr += sizeof(n->terminal);
            memcpy(ptr, n->name.data(), node_name_len);

#endif

            compiled_node.insert(
                    compiled_node.cend(),
                    compiled_tree.begin(),
                    compiled_tree.end()
            );
            compiled_tree = std::move(compiled_node);

            total_node_len += node_len;

            if (!node_stack.empty()) {
                auto next_frame = node_stack.pop();

                if (frame.parent == next_frame.parent) {
                    /*
                     * This node is a sibling of currently processed node, add
                     * the lengths currently processed node including its
                     * subtree and lengths of previously processed siblings
                     * along with their respective subtrees to the length of the
                     * subtree of its parent.
                     */
                    next_frame.parent_tree_len +=
                        frame.parent_tree_len + node_len;
                } else if (frame.parent == next_frame.nodeptr) {
                    /*
                     * This node is the parent of currently and previously
                     * processed nodes, add the length currently processed node
                     * including its subtree and lengths of previously processed
                     * siblings along with their respective subtrees to the
                     * length of its subtree.
                     */
                    next_frame.tree_len +=
                        frame.parent_tree_len + node_len;
                }

                node_stack.push(next_frame);
            }
        }

        return total_node_len;
    }

    static
    void query_args(
            const char* in,
            typename node::size_type len,
            qargstype &qargs
    ) {
        string_view target(in, len);
        hermes::url::streamdecode<>(target, qargs, true);
    }

    inline bool match_node(
            const compiled_tree_datatype *candidate,
            const char *name,
            typename node::size_type name_length,
            argstype &args,
            typename node::size_type &args_idx
    ) {

        // wildcard, parameter, equal
        if (candidate[name_offset] == '*') {
            /* use '*' for wildcards */

            return true;

        } else if (candidate[name_offset] == ':') {
            // parameter

            if (args_idx == args.size()) {
                // todo: push this pointer on the stack of args!
                args.push_back(string_view({name, name_length}));

                /* maintain index of args to backtrack */
                args_idx = args.size();
            } else {
                args.resize(args_idx + 1);
                /*
                 * Update args array at args_idx instead of appending
                 * We will always backtrack to the args_idx corresponding to
                 * current URL segment
                 */
                args[args_idx++] = string_view({name, name_length});
            }

            return true;

        } else if (node_name_length(candidate) == name_length &&
                !memcmp(candidate + name_offset, name, name_length)) {
            return true;
        }

        return false;
    }

    /* Deprecated */
    inline const char *find_node(
            const char *parent_node,
            const char *name,
            std::size_t name_length
    ) {

        unsigned short nodeLength = *(unsigned short*)&parent_node[0];
        unsigned short nodeNameLength = *(unsigned short*)&parent_node[2];

        //std::cout << "Finding node: <" << std::string(name, name_length)
        //    << ">" << std::endl;

        const char *stoppp = parent_node + nodeLength;
        for (
                const char *candidate = parent_node + 6 + nodeNameLength;
                candidate < stoppp;
        ) {

            unsigned short nodeLength = *(unsigned short*)&candidate[0];
            unsigned short nodeNameLength = *(unsigned short*)&candidate[2];

            // whildcard, parameter, equal
            if (nodeNameLength == 0) {
                return candidate;
            } else if (candidate[6] == ':') {
                // parameter

                // todo: push this pointer on the stack of args!
                args.get().push_back(string_view({name, name_length}));

                return candidate;
            } else if (
                    nodeNameLength == name_length &&
                    !memcmp(candidate + 6, name, name_length)
            ) {
                return candidate;
            }

            candidate = candidate + nodeLength;
        }

        return nullptr;
    }

    // returns next slash from start or end
    inline const char *next_segment(
            const char *start,
            const char *end,
            char delimiter = '/'
    ) {
        const char *stop = (const char*) memchr(start, delimiter, end - start);
        return stop ? stop : end;
    }

    inline void push_children(
            const char *segment,
            const compiled_tree_datatype *node,
            typename node::size_type args_idx
    ) {

        for (
                const compiled_tree_datatype *child =
                    node + name_offset + node_name_length(node);
                child < node + node_length(node);
                child = child + node_length(child)
        ) {
            route_stack.push({segment, child, args_idx});
        } 
    }

    inline bool store_match(
            const compiled_tree_datatype *&store,
            const compiled_tree_datatype *match
    ) {
        if (!match) {
            return false;
        }

        if (!store) {
            store = match;
            return true;
        }

        const unsigned short store_prio = node_priority(store);
        const unsigned short match_prio = node_priority(match);

        if (store_prio > match_prio) {
            return false;
        }

        if (
                store_prio == match_prio &&
                node_abs_priority(store) >= node_abs_priority(match)
        ) {
            return false;
        }

        store = match;

        return true;
    }

    // should take method also!
    inline handlertype* lookup(
            const char *url,
            typename node::size_type length
    ) {

        const compiled_tree_datatype *found = nullptr;

        const compiled_tree_datatype *compiled_node =
            (compiled_tree_datatype*)compiled_tree.data();

        const char *start = url;
        const char *stop = start + length; // This assignment is for reuse only
        const char *end_ptr = next_segment(start, stop, '?');

        if (end_ptr != stop) {
            query_args(end_ptr + 1, length - (end_ptr - start) - 1, qargs);
        }

        route_stack.clear();

        /* Push children on to stack */
        push_children(start, compiled_node, 0);

        while (!route_stack.empty()) {
            auto frame = route_stack.pop();

            /* Fetch URL segment ptr */
            start = frame.segptr;

            /* Fetch trie node ptr */
            compiled_node = frame.nodeptr;

            /* Get the end of current segment */
            stop = next_segment(start, end_ptr);

            //std::cout << "Matching(" << std::string(start, stop - start)
            //      << ")" << std::endl;

            if (
                    !match_node(
                        compiled_node,
                        start,
                        stop - start,
                        route_args,
                        frame.args_idx
                    )
            ) {
                continue;
            }

            /* Move to next URL segment */
            start = stop + 1;

            /* Check if we have reached the end of URL string and trie node is
             * terminal */
            if (
                    (stop == end_ptr || start == end_ptr) &&
                    is_terminal(compiled_node)
            ) {

                if (store_match(found, compiled_node)) {
                    std::swap(args, route_args);
                }
                continue;
            }
            
            /* Push children on to stack */
            push_children(start, compiled_node, frame.args_idx);
        }

        /* Deprecated */
        IF_CONSTEXPR (false) {
            do {
                stop = next_segment(start, end_ptr);

                //std::cout << "Matching(" << std::string(start, stop - start)
                //    << ")" << std::endl;

                if(
                        nullptr == (
                            compiled_node =
                            find_node(compiled_node, start, stop - start)
                        )
                ) {
                    return nullptr;
                }

                start = stop + 1;
            } while (stop != end_ptr);
        }

        return found ? node_handler(found) : nullptr;
    }

public:
    http_router() {
        // maximum 100 parameters
        route_args.get().reserve(100);
        args.get().reserve(100);
    }

    ~http_router() = default;
        
    void add(
            const char *method,
            const char *pattern,
            const handlertype& handler
    ) {

        auto handler_ptr = std::make_unique<handlertype>(std::move(handler));
        if (!handler_ptr) {
            throw std::bad_alloc();
        }

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

            //std::cout << "Segment(" << std::string(start, stop - start)
            //    << ")" << std::endl;

            nodes.push_back(
                    {
                        start,
                        static_cast<string_view::size_type>(stop - start)
                    }
            );

            start = stop + 1;
        } while (stop != end_ptr && start != end_ptr);

        add_nodes(nodes, std::move(handler_ptr));

        compile();
    }

    void add(
            const std::string &method,
            const std::string &pattern,
            const handlertype& handler
    ) {

        add(method.c_str(), pattern.c_str(), handler);
    }

    void compile() {
        compiled_tree.clear();
        compile_tree(tree);
    }

    void route(
            const char *method,
            unsigned int method_length,
            const char *url,
            unsigned int url_length,
            userdata userData
    ) {

        /* Prepend method to URL */
        char target[method_length + url_length + 1];
#ifdef __GNUC__

        auto ptr = mempcpy(target, method, method_length);
        ptr = mempcpy(ptr, url, url_length);
        *static_cast<char*>(ptr) = '\0';

#else

        memcpy(target, method, method_length);
        memcpy(target + method_length, url, url_length);
        target[sizeof(target) - 1] = '\0';

#endif

        auto handler = lookup(target, sizeof(target) - 1);

        if (handler) {
            (*handler)(userData, args, qargs);
        }

        route_args.get().clear();
        args.get().clear();
        qargs.clear();
    }
};

#endif // HTTPROUTER_HPP
