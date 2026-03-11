module cpp_list;

import std.exception : enforce;
import std.typecons : Tuple;
import std.algorithm : swap;
// =========================
// list (doubly linked list)
// =========================
template list(T)
{
    struct list
    {
        // Node は GC 管理のポインタで扱う
        private struct Node
        {
            T value;
            Node* prev;
            Node* next;

            this(T v)
            {
                value = v;
                prev = null;
                next = null;
            }
        }

        private Node* head = null;
        private Node* tail = null;
        private size_t _size = 0;

        // value_type alias
        alias value_type = T;

        // iterator
        struct iterator
        {
            private Node* node;

            this(Node* n) { node = n; }

            bool opEquals(const iterator other) const { return node == other.node; }

            // prefix ++
            void opUnary(string op)() if (op == "++")
            {
                enforce(node !is null, "incrementing end() iterator");
                node = node.next;
            }

            // postfix ++
            iterator opUnaryRight(string op)() if (op == "++")
            {
                auto tmp = this;
                enforce(node !is null, "incrementing end() iterator");
                node = node.next;
                return tmp;
            }

            // prefix --
            void opUnary(string op)() if (op == "--")
            {
                enforce(node !is null, "decrementing begin() iterator");
                node = node.prev;
            }

            // postfix --
            iterator opUnaryRight(string op)() if (op == "--")
            {
                auto tmp = this;
                enforce(node !is null, "decrementing begin() iterator");
                node = node.prev;
                return tmp;
            }

            // deref
            ref T opUnary(string op)() if (op == "*")
            {
                enforce(node !is null, "dereferencing end() iterator");
                return node.value;
            }

            // allow -> like access to value (not necessary but convenient)
            ref T opDispatch(string s)() if (s == "value" || s == "allow")
            {
                enforce(node !is null, "dereferencing end() iterator");
                return node.value;
            }
        }

        // begin / end
            iterator begin() { return iterator(head); }
            iterator end() { return iterator(null); }

        // size / empty
        size_t size() const { return _size; }
        bool empty() const { return _size == 0; }

        // front / back
        ref T front()
        {
            enforce(head !is null, "list is empty");
            return head.value;
        }

        ref T back()
        {
            enforce(tail !is null, "list is empty");
            return tail.value;
        }

        // push_back / push_front
        void push_back(T v)
        {
            auto n = new Node(v);
            if (tail is null)
            {
                head = tail = n;
            }
            else
            {
                tail.next = n;
                n.prev = tail;
                tail = n;
            }
            ++_size;
        }

        void push_front(T v)
        {
            auto n = new Node(v);
            if (head is null)
            {
                head = tail = n;
            }
            else
            {
                head.prev = n;
                n.next = head;
                head = n;
            }
            ++_size;
        }

        // pop_back / pop_front
        T pop_back()
        {
            enforce(tail !is null, "pop_back from empty list");
            auto v = tail.value;
            auto p = tail.prev;
            if (p is null)
            {
                head = tail = null;
            }
            else
            {
                p.next = null;
                tail = p;
            }
            --_size;
            return v;
        }

        T pop_front()
        {
            enforce(head !is null, "pop_front from empty list");
            auto v = head.value;
            auto n = head.next;
            if (n is null)
            {
                head = tail = null;
            }
            else
            {
                n.prev = null;
                head = n;
            }
            --_size;
            return v;
        }

        // insert before position it, returns iterator to inserted element
        iterator insert(iterator pos, T v)
        {
            // pos.node may be null (insert at end)
            if (pos.node is null)
            {
                push_back(v);
                return iterator(tail);
            }

            auto cur = pos.node;
            auto n = new Node(v);
            n.next = cur;
            n.prev = cur.prev;
            cur.prev = n;
            if (n.prev !is null)
                n.prev.next = n;
            else
                head = n;
            ++_size;
            return iterator(n);
        }

        // erase element at pos, returns iterator to next element
        iterator erase(iterator pos)
        {
            enforce(pos.node !is null, "erase end() iterator");
            auto cur = pos.node;
            auto nxt = cur.next;
            if (cur.prev !is null)
                cur.prev.next = cur.next;
            else
                head = cur.next;

            if (cur.next !is null)
                cur.next.prev = cur.prev;
            else
                tail = cur.prev;

            // Node will be GC-collected
            --_size;
            return iterator(nxt);
        }

        // clear
        void clear()
        {
            head = tail = null;
            _size = 0;
        }

        // find first element equal to value (linear)
        iterator find(T value)
        {
            for (auto it = begin(); it != end(); ++it)
            {
                if (*it == value)
                    return it;
            }
            return end();
        }

        // splice single element from other before pos (optional convenience)
        void splice(iterator pos, ref list other, iterator it)
        {
            enforce(it.node !is null, "splice from end() not allowed");
            // detach node from other
            auto n = it.node;
            if (n.prev !is null) n.prev.next = n.next; else other.head = n.next;
            if (n.next !is null) n.next.prev = n.prev; else other.tail = n.prev;
            --other._size;

            // insert before pos
            if (pos.node is null)
            {
                // insert at end
                if (tail is null)
                {
                    head = tail = n;
                    n.prev = n.next = null;
                }
                else
                {
                    tail.next = n;
                    n.prev = tail;
                    n.next = null;
                    tail = n;
                }
            }
            else
            {
                auto cur = pos.node;
                n.next = cur;
                n.prev = cur.prev;
                cur.prev = n;
                if (n.prev !is null) n.prev.next = n; else head = n;
            }
            ++_size;
        }
    }
}

// =========================
// unittests
// =========================
unittest
{
    // list test
    alias L = list!int;
    L lst;
    assert(lst.empty);
    lst.push_back(1);
    lst.push_back(2);
    lst.push_front(0);
    assert(lst.size == 3);
    assert(lst.front == 0);
    assert(lst.back == 2);

    auto it = lst.begin();
    assert(*it == 0);
    ++it;
    assert(*it == 1);

    // insert before current it (which points to 1)
    lst.insert(it, 5); // list: 0,5,1,2
    assert(lst.size == 4);

    // iterate and collect
    int sum = 0;
    for (auto i = lst.begin(); i != lst.end(); ++i)
        sum += *i;
    assert(sum == 0 + 5 + 1 + 2);

    // erase the 5
    it = lst.find(5);
    assert(it != lst.end());
    lst.erase(it);
    assert(lst.size == 3);

    assert(lst.pop_front == 0);
    assert(lst.pop_back == 2);
    assert(lst.size == 1);
    lst.clear();
    assert(lst.empty);
}
