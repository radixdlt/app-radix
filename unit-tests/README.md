# Unit tests

## Prerequisite

Be sure to have installed:

- CMake >= 3.10
- CMocka >= 1.1.5

and for code coverage generation:

- lcov >= 1.14

## Overview

In `unit-tests` folder, compile with

```sh
cmake -Bbuild -H. && make -C build
```

and run tests with

```sh
CTEST_OUTPUT_ON_FAILURE=1 make -C build test
```

Append ` ARGS="-V"` in the end if you want to see output even if tests succeed. Otherwise `print_message` output only seems to be displayed if tests failed.

Or just use this nice one liner:

```sh
rm -rf build && cmake -Bbuild -H. && make -C build && CTEST_OUTPUT_ON_FAILURE=1 make -C build test ARGS="-V"

```

## Generate code coverage

Just execute in `unit-tests` folder

```
./gen_coverage.sh
```

it will output `coverage.total` and `coverage/` folder with HTML details (in `coverage/index.html`).
