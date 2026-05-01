/*
 * Tier 1 — use-after-free (C++ variant).
 *
 * Idiomatic C++ shape: raw owning pointer with manual delete, then
 * a method invoked on the dangling pointer. Real-world variant:
 * raw `T*` member that escapes the owner's lifetime, and a callback
 * that uses it.
 *
 * Knowledge: [[Memory/Knowledge/wnapi_heap_internals]]
 * CWE-416.
 */
#include <iostream>
#include <string>

class Resource {
public:
    explicit Resource(std::string name) : name_(std::move(name)) {}
    void log() const { std::cout << "Resource: " << name_ << "\n"; }
private:
    std::string name_;
};

class Manager {
public:
    void open(const std::string& n) { res_ = new Resource(n); }
    void close() { delete res_; /* NOT nulled */ }
    void heartbeat() { if (res_) res_->log(); }     // virtual on dangling pointer
private:
    Resource* res_ = nullptr;
};

int main() {
    Manager m;
    m.open("db");
    m.close();
    m.heartbeat();                          // UAF: virtual call on freed object
    return 0;
}
