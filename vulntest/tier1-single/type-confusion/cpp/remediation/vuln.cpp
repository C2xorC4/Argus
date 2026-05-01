/*
 * Tier 1 — type-confusion / C++ — remediation.
 *
 * Use dynamic_cast or virtual dispatch. dynamic_cast checks RTTI
 * and returns nullptr (or throws for references) on mismatch.
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
    /* either: virtual dispatch (Shape::area() is virtual) — preferred */
    return s ? s->area() : 0.0;
    /* or: dynamic_cast guarded
       Circle* c = dynamic_cast<Circle*>(s);
       return c ? c->area() : 0.0;
    */
}

int main(int argc, char** argv) {
    Shape* s = (argc > 1 && std::string(argv[1]) == "rect")
               ? static_cast<Shape*>(new Rectangle(3, 4))
               : static_cast<Shape*>(new Circle(5));
    std::cout << "area=" << get_radius(s) << "\n";
    delete s;
    return 0;
}
