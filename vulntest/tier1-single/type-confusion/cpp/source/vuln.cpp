/*
 * Tier 1 — type confusion (C++ variant).
 *
 * Two classes share a base; downcast via static_cast (no RTTI check)
 * lets a derived-A pointer be used as derived-B. The vtable layout
 * differs; calling a virtual method dispatches through the wrong
 * vtable slot.
 *
 * The classical browser-RCE chain begins here: type confusion in
 * a JS engine produces an arbitrary-read or pointer dereference.
 *
 * Knowledge: [[Memory/Knowledge/ec_undefined_behavior_taxonomy]]
 *            [[Memory/Knowledge/bhg_unsafe_pointer_patterns]]
 * CWE-843.
 */
#include <iostream>
#include <string>

class Shape {
public:
    virtual ~Shape() = default;
    virtual std::string kind() const = 0;
    virtual double area() const { return 0.0; }
};

class Circle : public Shape {
public:
    explicit Circle(double r) : radius_(r) {}
    std::string kind() const override { return "circle"; }
    double area() const override { return 3.14159 * radius_ * radius_; }
private:
    double radius_;
};

class Rectangle : public Shape {
public:
    Rectangle(double w, double h) : w_(w), h_(h) {}
    std::string kind() const override { return "rect"; }
    double area() const override { return w_ * h_; }
private:
    double w_, h_;
};

double get_radius(Shape* s) {
    /* sink: static_cast bypasses RTTI. If s actually points to a
       Rectangle, this reads w_ as if it were radius_. */
    Circle* c = static_cast<Circle*>(s);
    return c->area();
}

int main(int argc, char** argv) {
    Shape* s = (argc > 1 && std::string(argv[1]) == "rect")
               ? static_cast<Shape*>(new Rectangle(3, 4))
               : static_cast<Shape*>(new Circle(5));
    std::cout << "area=" << get_radius(s) << "\n";
    delete s;
    return 0;
}
