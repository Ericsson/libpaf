# Pathfinder Client Library

Pathfinder (or paf, for short) is a minimal name service discovery
system.

The Pathfinder Client Library (or libpaf, for short) is a C library
used to access one or more Pathfinder service discovery domains.

## Installation

The Pathfinder Client Library is implemented in C. Its runtime and
build-time dependencies are libjansson and libxcm. Autotools is a
build-time dependency.

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

## More Information

You can find more information about Pathfinder in the server git
repository 'paf'. There are also a number of Pathfinder screencasts on
Ericsson Play.

Introduction and Overview:
https://play.ericsson.net/media/t/0_bewz17us
Command-line Demo:
https://play.ericsson.net/media/t/0_z8c77wsc
Tracing and Debugging:
https://play.ericsson.net/media/t/0_y1h8rkgi
