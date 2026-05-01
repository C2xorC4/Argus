/*
 * Tier 1 — stack-overflow / C++ — remediation.
 *
 * Idiomatic C++ fix: replace the C-style char buffer with std::string,
 * which grows dynamically and bounds itself. Alternative: std::setw()
 * on operator>> caps input length at the buffer size.
 */
#include <iostream>
#include <string>

class Greeter {
public:
    void promptAndGreet() {
        std::string name;            // grows as needed; no fixed bound to overflow
        std::cout << "Name: ";
        std::cin >> name;
        std::cout << "Hello, " << name << "\n";
    }
};

int main() {
    Greeter g;
    g.promptAndGreet();
    return 0;
}
