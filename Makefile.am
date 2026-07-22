# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Pattern rule to print variables, e.g. make print-top_srcdir
print-%:
	@echo $* = $($*)

ACLOCAL_AMFLAGS = -I build-aux/m4
SUBDIRS = src
if ENABLE_MAN
SUBDIRS += doc/man
endif
SUBDIRS += params
.PHONY: FORCE

export PYTHONPATH

if BUILD_BITCOIN_LIBS
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libbitcoinconsensus.pc
endif

# BATHRON is daemon-only (GUI removed): no Qt binary, no macOS .app/DMG, no
# Windows NSIS installer. Only the daemon + CLI + tx tool are built/packaged.
BITCOIND_BIN=$(top_builddir)/src/$(BITCOIN_DAEMON_NAME)$(EXEEXT)
BITCOIN_CLI_BIN=$(top_builddir)/src/$(BITCOIN_CLI_NAME)$(EXEEXT)

DIST_DOCS = \
  README.md \
  $(wildcard doc/*.md) \
  $(wildcard doc/release-notes/*.md)
DIST_CONTRIB = \
           $(top_srcdir)/contrib/devtools \
           $(top_srcdir)/contrib/seeds

DIST_SHARE = \
           $(top_srcdir)/share/genbuild.sh \
           $(top_srcdir)/share/rpcauth

DIST_CARGO = \
           $(top_srcdir)/.cargo/config.offline \
           $(top_srcdir)/Cargo.lock \
           $(top_srcdir)/Cargo.toml \
           $(top_srcdir)/rust-toolchain \
           $(top_srcdir)/params/install-params.sh

BIN_CHECKS=$(top_srcdir)/contrib/devtools/symbol-check.py \
           $(top_srcdir)/contrib/devtools/security-check.py \
           $(top_srcdir)/contrib/devtools/pixie.py

LINUX_PACKAGING = $(top_srcdir)/share/pixmaps/bathron16.xpm \
  $(top_srcdir)/share/pixmaps/bathron32.xpm \
  $(top_srcdir)/share/pixmaps/bathron128.png

COVERAGE_INFO = baseline.info \
  test_bathron_filtered.info total_coverage.info \
  baseline_filtered.info \
  test_bathron_coverage.info test_bathron.info

dist-hook:
	-$(GIT) archive --format=tar HEAD -- src/clientversion.cpp | $(AMTAR) -C $(top_distdir) -xf -

$(BITCOIND_BIN): FORCE
	$(MAKE) -C src $(@F)

$(BITCOIN_CLI_BIN): FORCE
	$(MAKE) -C src $(@F)

if USE_LCOV
LCOV_FILTER_PATTERN= \
        -p "/usr/local/" \
        -p "/usr/include/" \
        -p "/usr/lib/" \
        -p "/usr/lib64" \
        -p "src/leveldb/" \
        -p "src/bench/" \
        -p "src/crc32c/" \
        -p "src/crypto/ctaes/" \
        -p "src/univalue" \
        -p "src/secp256k1" \
        -p "depends"

baseline.info:
	$(LCOV) -c -i -d $(abs_builddir)/src -o $@

baseline_filtered.info: baseline.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

test_bathron.info: baseline_filtered.info
	$(MAKE) -C src/ check
	$(LCOV) -c $(LCOV_OPTS) -d $(abs_builddir)/src -t test_bathron -o $@
	$(LCOV) -z $(LCOV_OPTS) -d $(abs_builddir)/src

test_bathron_filtered.info: test_bathron.info
	$(abs_builddir)/contrib/filter-lcov.py $(LCOV_FILTER_PATTERN) $< $@
	$(LCOV) -a $@ $(LCOV_OPTS) -o $@

test_bathron_coverage.info: baseline_filtered.info test_bathron_filtered.info
	$(LCOV) -a $(LCOV_OPTS) baseline_filtered.info -a test_bathron_filtered.info -o $@

total_coverage.info: test_bathron_filtered.info
	$(LCOV) -a $(LCOV_OPTS) baseline_filtered.info -a test_bathron_filtered.info -o $@ | $(GREP) "\%" | $(AWK) '{ print substr($$3,2,50) "/" $$5 }' > coverage_percent.txt

test_bathron.coverage/.dirstamp:  test_bathron_coverage.info
	$(GENHTML) -s $(LCOV_OPTS) $< -o $(@D)
	@touch $@

total.coverage/.dirstamp: total_coverage.info
	$(GENHTML) -s $(LCOV_OPTS) $< -o $(@D)
	@touch $@

cov: test_bathron.coverage/.dirstamp total.coverage/.dirstamp

endif

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST = $(DIST_SHARE) $(DIST_CONTRIB) $(DIST_DOCS) $(DIST_CARGO) $(LINUX_PACKAGING) $(BIN_CHECKS)

EXTRA_DIST += \
    test/fuzz

EXTRA_DIST += \
    test/util/bitcoin-util-test.py \
    test/util/data/bitcoin-util-test.json \
    test/util/data/blanktxv1.hex \
    test/util/data/blanktxv1.json \
    test/util/data/tt-delin1-out.hex \
    test/util/data/tt-delin1-out.json \
    test/util/data/tt-delout1-out.hex \
    test/util/data/tt-delout1-out.json \
    test/util/data/tt-locktime317000-out.hex \
    test/util/data/tt-locktime317000-out.json \
    test/util/data/tx394b54bb.hex \
    test/util/data/txcreate1.hex \
    test/util/data/txcreate1.json \
    test/util/data/txcreate2.hex \
    test/util/data/txcreate2.json \
    test/util/data/txcreatescript1.hex \
    test/util/data/txcreatescript1.json \
    test/util/data/txcreatesign.hex \
    test/util/data/txcreatesign.json \
    test/util/data/pre_hd_wallet.dat \
    test/util/rpcauth-test.py

.INTERMEDIATE: $(COVERAGE_INFO)

DISTCHECK_CONFIGURE_FLAGS = --enable-man

doc/doxygen/.stamp: doc/Doxyfile FORCE
	$(MKDIR_P) $(@D)
	$(DOXYGEN) $^
	$(AM_V_at) touch $@

if HAVE_DOXYGEN
docs: doc/doxygen/.stamp
else
docs:
	@echo "error: doxygen not found"
endif

clean-docs:
	rm -rf doc/doxygen

clean-local: clean-docs
	rm -rf coverage_percent.txt test_bathron.coverage/ total.coverage/ test/tmp/ cache/
	rm -rf test/cache share/rpcauth/__pycache__
