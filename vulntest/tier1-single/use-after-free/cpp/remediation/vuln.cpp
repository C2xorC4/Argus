/*
 * Tier 1 — UAF / C++ — remediation.
 *
 * Replace raw owning pointer with std::unique_ptr. Lifetime is
 * bounded to the owner; close() resets the unique_ptr, which is
 * a guaranteed-null state.
 */
#include <iostream>
#include <memory>
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
    void open(const std::string& n) { res_ = std::make_unique<Resource>(n); }
    void close() { res_.reset(); }
    void heartbeat() { if (res_) res_->log(); }
private:
    std::unique_ptr<Resource> res_;
};

int main() {
    Manager m;
    m.open("db");
    m.close();
    m.heartbeat();
    return 0;
}
