# Pathfinder Client Library

Pathfinder is a light-weight service discovery system.

The Pathfinder Client Library `libpaf` is a C library used to access
one or more Pathfinder service discovery domains, either as a service
producer or consumer.

For more information, see the Pathfinder server README.

## Installation

The Pathfinder Client Library is implemented in C. Its runtime and
build-time dependencies are libjansson and libxcm (API/ABI version
0.13 or later). Autotools is a build-time dependency.

To build and install libpaf, run:

autoreconf -i && ./configure && make install

## Test Suites

The source tree includes both unit and component-level tests. The
component-level test are an integration test, running against a real
Pathfinder server. Either the Pathfinder server (pafd) is installed on
the system ("make install"), or the 'paf' module needs to be included
in the PYTHONPATH, and the PATH needs to include the 'pafd'
executable.

If available, valgrind will be used when running the test suites.

Both types of tests use the 'utest' test framework, included in the
source tree.

To run the tests, issue:
make check

## Documentation

API documentation in Doxygen format is available in paf.h. `make
doxygen` will create HTML version. If the `pdflatex` tool is
installed, a PDF version will also be produced.

An online copy of this API version's documentation can be found here:
https://ericsson.github.io/libpaf/api/0.0/
