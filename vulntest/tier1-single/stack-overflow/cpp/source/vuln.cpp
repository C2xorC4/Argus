/*
 * Tier 1 — stack buffer overflow (C++ variant).
 *
 * Idiomatic C++ shape: fixed-size char member of a class, populated
 * via `std::cin >> buf`. operator>> on a raw char[] is unbounded —
 * the C++ standard library carries the same hazard as raw strcpy
 * but in idiomatic-looking code.
 *
 * Knowledge: [[Memory/Knowledge/hw_stack_overflow_mechanics]]
 * CWE-121, CWE-242 (use of inherently dangerous function in C++).
 */
#include <iostream>
#include <cstring>

class Greeter {
public:
    void promptAndGreet() {
        char name[64];
        std::cout << "Name: ";
        std::cin >> name;            // sink: unbounded operator>>(char*)
        std::cout << "Hello, " << name << "\n";
    }
};

int main() {
    Greeter g;
    g.promptAndGreet();              // source: stdin → tainted
    return 0;
}
