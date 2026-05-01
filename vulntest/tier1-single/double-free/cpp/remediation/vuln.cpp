/*
 * Tier 1 — double-free / C++ — remediation.
 *
 * Two viable fixes:
 *   1. Rule of Three — implement copy ctor + copy assignment + dtor.
 *   2. Replace raw owning pointer with smart pointer (preferred).
 *
 * Use std::unique_ptr; the copy is then a compile error (forces
 * explicit ownership transfer via std::move) — strictly better.
 */
#include <iostream>
#include <memory>
#include <string>

class Owner {
public:
    explicit Owner(const std::string& n) : data_(std::make_unique<std::string>(n)) {}
    void show() const { std::cout << *data_ << "\n"; }
private:
    std::unique_ptr<std::string> data_;
    /* unique_ptr is non-copyable; compiler-generated copy of Owner
       fails to compile, forcing the developer to either move or
       implement explicit copy semantics. */
};

int main() {
    Owner a("hello");
    Owner b = std::move(a);          // explicit ownership transfer
    b.show();
    return 0;
}
