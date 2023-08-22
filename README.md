# Pathfinder Client Library

Pathfinder is a light-weight service discovery system.

The Pathfinder Client Library `libpaf` is a C library used to access
one or more Pathfinder service discovery domains, either as a service
provider or consumer. The library is an implementation of the
[Pathfinder
protocol](https://github.com/Ericsson/paf/blob/master/doc/PROTOCOL.md)
version 2.

For more detailed information, see the [Pathfinder
server](https://github.com/Ericsson/paf/blob/master/README.md).

## Installation

The Pathfinder Client Library is implemented in C.

Dependencies:

* libjansson
* libxcm 1.5.0 or later (i.e., API version 0.20 or higher)
* Automake
* GNU readline

To build and install libpaf, run:

```
autoreconf -i && ./configure && make install
```

## Test Suites

The libpaf source tree hosts unit and component-level tests for the
library. The component-level test suite is an integration test,
running against a real Pathfinder server.

The component-level tests will look for a `pafd` binary in the
PATH. In addition, the 'paf' Python module needs to be included in the
PYTHONPATH.

If available, valgrind will be used when running the test suites.

Both types of tests use the 'utest' test framework, included in the
source tree.

To run the tests, issue:

```
make check
```

In case the `tpafd` (or any other) server is to be used by integration
tests, use:

```
PAFD=tpafd make check
```

For the test suite to cover functionality related to network
namespaces, the CAP_SYS_ADMIN capability is required.

## Documentation

API documentation in Doxygen format is available in paf.h. `make
doxygen` will create HTML version. If the `pdflatex` tool is
installed, a PDF version will also be produced.

An online copy of this API version's documentation can be found here:
https://ericsson.github.io/libpaf/api/0.1/
