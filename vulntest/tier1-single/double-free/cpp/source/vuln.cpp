/*
 * Tier 1 — double-free (C++ variant).
 *
 * Two distinct unique_ptr-likes own the same raw pointer because of
 * a misguided "share via raw pointer" pattern. Real-world shape:
 * accidental copy of an owning struct that holds a raw pointer.
 *
 * Knowledge: [[Memory/Knowledge/wnapi_heap_internals]]
 * CWE-415.
 */
#include <iostream>
#include <string>

class Owner {
public:
    explicit Owner(const std::string& n) : data_(new std::string(n)) {}
    ~Owner() { delete data_; }                    // delete — but copy ctor copies raw pointer
    // intentionally no copy/move declarations — compiler-generated
    // shallow copy creates two Owners owning the same data_.

    void show() const { std::cout << *data_ << "\n"; }
private:
    std::string* data_;
};

int main() {
    Owner a("hello");
    Owner b = a;          // shallow copy — both a.data_ and b.data_ point to same heap object
    a.show();
    b.show();
    // a destructor deletes data_
    // b destructor deletes data_ again — double free
    return 0;
}
