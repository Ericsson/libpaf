ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -Werror

AM_CPPFLAGS = -I$(srcdir)/include -DSYSCONFDIR='"$(sysconfdir)"'

lib_LTLIBRARIES = libpaf.la

include_HEADERS = include/paf.h include/paf_props.h include/paf_value.h \
	include/paf_match.h include/paf_err.h

check_PROGRAMS = paftest

noinst_PROGRAMS = client

bin_SCRIPTS = app/pafappc

# For information on how to update these numbers, see:
# https://www.gnu.org/software/libtool/manual/html_node/Libtool-versioning.html#Libtool-versioning
PAF_VERSION_CURRENT=@PAF_ABI_MINOR_VERSION@
PAF_VERSION_REVISION=@PAF_PATCH_VERSION@
PAF_VERSION_AGE=$(PAF_VERSION_CURRENT)

libpaf_la_SOURCES = src/util.c src/epoll_reg.c src/ptimer.c src/log.c \
	src/service.c src/match.c src/sub.c src/sd.c src/proto_ta.c \
	src/msg.c src/paf_value.c src/paf_props.c src/filter.c src/err.c \
	src/conf.c src/link.c src/server_conf.c src/domain_conf.c src/paf.c

libpaf_la_LDFLAGS = -Wl,--version-script=$(srcdir)/src/libpaf.vs \
	-version-info $(PAF_VERSION_CURRENT):$(PAF_VERSION_REVISION):$(PAF_VERSION_AGE)
libpaf_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/src
libpaf_la_CFLAGS = $(AM_CFLAGS) -Wextra

if LTTNG
libpaf_la_SOURCES += src/paf_lttng.c
libpaf_la_CPPFLAGS += -DPAF_LTTNG
libpaf_la_LDFLAGS += -llttng-ust
endif

UTEST_SOURCES = test/utest/utest.c test/utest/utestreport.c \
        test/utest/utesthumanreport.c
TEST_CPPFLAGS=-I$(srcdir)/test -I$(srcdir)/test/utest -I$(srcdir)/src

PAFTEST_TESTCASE_SOURCES = test/value_testcases.c test/props_testcases.c \
	test/filter_testcases.c test/service_testcases.c \
	test/sub_testcases.c test/sd_testcases.c test/domain_conf_testcases.c \
	test/paf_testcases.c

# These functions are included in the shared object, but their symbols
# aren't exported, so we need to link their object files into the test
# program
PAFTEST_UNITTEST_SOURCES = src/sub.c src/filter.c src/log.c \
	src/match.c src/service.c src/sd.c src/paf_props.c src/paf_value.c \
	src/server_conf.c src/domain_conf.c src/conf.c
paftest_SOURCES = $(PAFTEST_TESTCASE_SOURCES) $(UTEST_SOURCES) \
	src/util.c test/testutil.c $(PAFTEST_UNITTEST_SOURCES)
paftest_CPPFLAGS=$(AM_CPPFLAGS) $(TEST_CPPFLAGS)
paftest_LDADD = libpaf.la
paftest_LDFLAGS = -no-install

client_SOURCES = example/client.c
client_CFLAGS = $(AM_CFLAGS)
client_LDADD = libpaf.la

python_PYTHON = python/libpaf.py

PYTEST=py.test-3

.doxygen: doc/doxygen.conf $(include_HEADERS)
	doxygen doc/doxygen.conf && touch $@
if PDFLATEX
	make -C doc/latex && mv doc/latex/refman.pdf doc/libpaf.pdf
endif

doxygen: .doxygen

clean-local:
	rm -f .doxygen
	rm -f .testcert
	rm -rf test/cert
	rm -rf doc/html
	rm -rf test/domains
if PDFLATEX
	rm -rf doc/latex
	rm -f doc/libpaf.pdf
endif

distclean-local:
	rm -rf autom4te.cache m4
	rm -f Makefile.in aclocal.m4 compile config.guess include/stamp-h1 \
		config.sub configure depcomp install-sh ltmain.sh missing \
		common/config.h.in
	find . -name \*~ -print0 | xargs -0 rm -f

testcert: .testcert

.testcert: test/cert.yaml
	./test/gencert.py < test/cert.yaml && touch .testcert

verify-versions: all
	./test/verify_versions.py $(srcdir)/include/paf.h \
		$(srcdir)/README.md $(builddir) \
		@PAF_ABI_MAJOR_VERSION@ @PAF_ABI_MINOR_VERSION@ \
		@PAF_MAJOR_VERSION@ @PAF_MINOR_VERSION@ \
		@PAF_PATCH_VERSION@

paftest-run: testcert paftest
	./paftest -c $(TESTS)

pytest-run: testcert all
	export PYTHONPATH=$(PWD)/python:$$PYTHONPATH && \
	cd test && \
	$(PYTEST) -v -s $(PYTESTS)

paftest-run-valgrind: testcert paftest
	IN_VALGRIND=1 valgrind --tool=memcheck --leak-check=full -q \
		--suppressions=test/libc.supp \
		--suppressions=test/xcm.supp \
		--suppressions=test/lttng.supp \
		--num-callers=20 ./paftest -v -c $(TESTS)

BASIC_TEST_TARGETS=verify-versions paftest-run

if VALGRIND
TEST_TARGETS=paftest-run-valgrind $(BASIC_TEST_TARGETS)
else
TEST_TARGETS=$(BASIC_TEST_TARGETS)
endif

TEST_TARGETS += pytest-run

check-local: $(TEST_TARGETS)

count:
	@echo "Public Client API:"
	@wc -l `git ls-files include | grep -E '\.h$$'`
	@echo "Library Implementation:"
	@wc -l `git ls-files src | grep -E '\.[ch]{1}$$'`
	@echo "Example code:"
	@wc -l `git ls-files example | grep -E '\.[ch]{1}$$'`
	@echo "Test suites:"
	@wc -l `git ls-files test | grep -E '\.[ch]{1}$$' | grep -v test/utest`
