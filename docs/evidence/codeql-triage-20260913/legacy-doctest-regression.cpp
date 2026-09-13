// Focused regression for the retained legacy test dependency, not the Rust app.
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_POSIX_SIGNALS
#include "3rdparty/test/doctest/doctest.h"
#include <stdexcept>
#include <string>

int main() {
  for (const size_t size : {0u, 1u, 10u, 22u, 23u, 24u, 64u, 129u}) {
    const std::string input(size, 'a');
    doctest::String actual(input.c_str());
    std::string expected(input);
    for (unsigned repeat = 0; repeat < 3; ++repeat) {
      actual += actual;
      expected += expected;
      if (std::string(actual.c_str()) != expected || actual.size() != expected.size())
        throw std::runtime_error("legacy String self-append corrupted its value");
    }
    actual += doctest::String("suffix");
    if (std::string(actual.c_str()) != expected + "suffix")
      throw std::runtime_error("legacy String independent append changed");
  }
}
