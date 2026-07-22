# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(HARDENED_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS) $(GPROF_CXXFLAGS) $(SANITIZER_CXXFLAGS)
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) $(HARDENED_CPPFLAGS) $(SODIUM_CFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(SQLITE3_CFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/rust/include
BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += $(UNIVALUE_CFLAGS)

LIBBITCOIN_SERVER=libbitcoin_server.a
LIBBITCOIN_COMMON=libbitcoin_common.a
LIBBITCOIN_CLI=libbitcoin_cli.a
LIBBITCOIN_UTIL=libbitcoin_util.a
LIBBITCOIN_CRYPTO=crypto/libbitcoin_crypto.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBSAPLING=libsapling.a
if ENABLE_ONLINE_RUST
LIBRUSTZCASH=$(top_builddir)/target/release/librustzcash.a
else
LIBRUSTZCASH=$(top_builddir)/target/$(RUST_TARGET)/release/librustzcash.a
endif

if ENABLE_ZMQ
LIBBITCOIN_ZMQ=libbitcoin_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBBITCOINCONSENSUS=libbitcoinconsensus.la
endif
if ENABLE_WALLET
LIBBITCOIN_WALLET=libbitcoin_wallet.a
endif

# Fallback for CARGO if not set by configure (e.g., Rust installed after configure)
CARGO ?= cargo

RUST_ENV_VARS = RUSTC="$(RUSTC)" TERM=dumb
RUST_BUILD_OPTS = --release

if ENABLE_ONLINE_RUST
# Ensure that .cargo/config does not exist
CARGO_CONFIGURED = $(top_srcdir)/.cargo/.configured-for-online
$(CARGO_CONFIGURED):
	$(AM_V_at)rm -f $(top_srcdir)/.cargo/.configured-for-offline $(top_srcdir)/.cargo/config
	$(AM_V_at)touch $@

else
# Enable dependency vendoring
RUST_BUILD_OPTS += --locked --offline
if HAVE_RUST_TARGET
RUST_BUILD_OPTS += --target $(RUST_TARGET)
endif

CARGO_CONFIGURED = $(top_srcdir)/.cargo/.configured-for-offline
$(CARGO_CONFIGURED): $(top_srcdir)/.cargo/config.offline
	$(AM_V_at)rm -f $(top_srcdir)/.cargo/.configured-for-online
	$(AM_V_at)cp $< $(top_srcdir)/.cargo/config
	$(AM_V_at)echo "directory = \"$(RUST_VENDORED_SOURCES)\"" >> $(top_srcdir)/.cargo/config
	$(AM_V_at)touch $@
endif

cargo-build: $(CARGO_CONFIGURED)
	$(RUST_ENV_VARS) $(CARGO) build $(RUST_BUILD_OPTS) --manifest-path $(top_srcdir)/Cargo.toml

$(LIBRUSTZCASH): cargo-build

$(LIBSECP256K1): $(wildcard secp256k1/src/*.h) $(wildcard secp256k1/src/*.c) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_CLI) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBSAPLING)

lib_LTLIBRARIES = $(LIBBITCOINCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += bathrond
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += bathron-cli bathron-tx
endif

LIBSAPLING_H = \
  sapling/sapling.h \
  bech32.h \
  sapling/key_io_sapling.h \
  sapling/sapling_core_write.h \
  sapling/sapling_util.h \
  sapling/prf.h \
  sapling/noteencryption.h \
  sapling/address.h \
  sapling/note.h \
  sapling/zip32.h \
  sapling/saplingscriptpubkeyman.h \
  sapling/incrementalmerkletree.h \
  sapling/sapling_transaction.h \
  sapling/transaction_builder.h \
  sapling/sapling_operation.h

.PHONY: FORCE cargo-build check-symbols check-security
# bathron core #
BITCOIN_CORE_H = \
  masternode/activemasternode.h \
  addrdb.h \
  addrman.h \
  attributes.h \
  arith_uint256.h \
  amount.h \
  base58.h \
  bip38.h \
  bloom.h \
  blocksignature.h \
  btcspv/btcspv.h \
  btcheaders/btcheaders.h \
  btcheaders/btcheadersdb.h \
  btcheaders/btcstate_provider.h \
  script/btcstate.h \
  burnclaim/burnclaim.h \
  burnclaim/burnclaimdb.h \
  burnclaim/killswitch.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/cpuid.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/merkle.h \
  consensus/validation.h \
  consensus/tx_verify.h \
  consensus/params.h \
  consensus/upgrades.h \
  primitives/block.h \
  primitives/transaction.h \
  core_io.h \
  cuckoocache.h \
  crypter.h \
  ctpl_stl.h \
  masternode/deterministicmns.h \
  masternode/evodb.h \
  masternode/mnauth.h \
  masternode/evonotificationinterface.h \
  masternode/providertx.h \
  masternode/specialtx_validation.h \
  masternode/blockproducer.h \
  consensus/mn_validation.h \
  flatdb.h \
  state/finality.h \
  state/quorum.h \
  masternode/masternode_meta_manager.h \
  addressbook.h \
  wallet/db.h \
  flatfile.h \
  fs.h \
  hash.h \
  httprpc.h \
  httpserver.h \
  indirectmap.h \
  node/init.h \
  masternode/init.h \
  key.h \
  key_io.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  logging.h \
  sapling/sapling_validation.h \
  state/finality.h \
  state/quorum.h \
  state/signaling.h \
  state/settlement.h \
  state/settlementdb.h \
  state/settlement_logic.h \
  state/settlement_builder.h \
  htlc/htlc.h \
  htlc/htlcdb.h \
  mapport.h \
  memusage.h \
  merkleblock.h \
  messagesigner.h \
  blockassembler.h \
  moneysupply.h \
  net/net.h \
  net/net_processing.h \
  net/netaddress.h \
  net/netbase.h \
  netmessagemaker.h \
  node/noui.h \
  policy/feerate.h \
  policy/fees.h \
  policy/policy.h \
  optional.h \
  operationresult.h \
  bathron_chainwork.h \
  prevector.h \
  protocol.h \
  pubkey.h \
  vrf.h \
  random.h \
  randomenv.h \
  reverse_iterate.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/register.h \
  rpc/server.h \
  saltedhasher.h \
  scheduler.h \
  script/descriptor.h \
  script/interpreter.h \
  script/keyorigin.h \
  script/script.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/conditional.h \
  script/script_error.h \
  serialize.h \
  node/shutdown.h \
  span.h \
  script/ismine.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  tinyformat.h \
  masternode/tiertwo_sync_state.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  guiinterface.h \
  guiinterfaceutil.h \
  uint256.h \
  undo.h \
  util/asmap.h \
  util/blockstatecatcher.h \
  util/system.h \
  util/macros.h \
  util/string.h \
  util/threadnames.h \
  util/validation.h \
  utilstrencodings.h \
  utilmoneystr.h \
  utiltime.h \
  util/vector.h \
  validation.h \
  validationinterface.h \
  version.h \
  wallet/hdchain.h \
  wallet/rpcwallet.h \
  wallet/scriptpubkeyman.h \
  destination_io.h \
  wallet/fees.h \
  wallet/init.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/walletutil.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h \
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh "$(abs_top_builddir)/src/obj/build.h" \
	  "$(abs_top_srcdir)"
libbitcoin_util_a-clientversion.$(OBJEXT): obj/build.h

# server: hud daemon
libbitcoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(NATPMP_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libbitcoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_server_a_SOURCES = \
  addrdb.cpp \
  addrman.cpp \
  bloom.cpp \
  blocksignature.cpp \
  chain.cpp \
  checkpoints.cpp \
  consensus/params.cpp \
  consensus/tx_verify.cpp \
  flatfile.cpp \
  masternode/deterministicmns.cpp \
  masternode/evodb.cpp \
  masternode/evonotificationinterface.cpp \
  masternode/mnauth.cpp \
  masternode/providertx.cpp \
  masternode/specialtx_validation.cpp \
  masternode/blockproducer.cpp \
  consensus/mn_validation.cpp \
  state/finality.cpp \
  state/metrics.cpp \
  state/quorum.cpp \
  state/signaling.cpp \
  masternode/masternode_meta_manager.cpp \
  httprpc.cpp \
  httpserver.cpp \
  node/init.cpp \
  masternode/init.cpp \
  dbwrapper.cpp \
  sapling/sapling_validation.cpp \
  merkleblock.cpp \
  mapport.cpp \
  net/net.cpp \
  net/net_processing.cpp \
  node/noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  bathron_chainwork.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/conditional.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/rpcevo.cpp \
  rpc/rpc_mn_stats.cpp \
  rpc/settlement.cpp \
  rpc/settlement_wallet.cpp \
  rpc/btcspv.cpp \
  btcspv/btcspv.cpp \
  rpc/burnclaim.cpp \
  burnclaim/burnclaim.cpp \
  burnclaim/burnclaimdb.cpp \
  burnclaim/killswitch.cpp \
  rpc/btcheaders.cpp \
  btcheaders/btcheaders.cpp \
  btcheaders/btcheadersdb.cpp \
  btcheaders/btcstate_provider.cpp \
  btcheaders/btcheaders_publisher.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  script/ismine.cpp \
  node/shutdown.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  sapling/sapling_txdb.cpp \
  txmempool.cpp \
  validation.cpp \
  validationinterface.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBSAPLING_H)

if ENABLE_ZMQ
libbitcoin_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libbitcoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif

# wallet: hud daemon (when wallet enabled)
libbitcoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_wallet_a_SOURCES = \
  bip38.cpp \
  addressbook.cpp \
  crypter.cpp \
  wallet/db.cpp \
  wallet/fees.cpp \
  wallet/init.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/hdchain.cpp \
  wallet/scriptpubkeyman.cpp \
  destination_io.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/walletutil.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBSAPLING_H)

# crypto primitives library
crypto_libbitcoin_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(PIC_FLAGS)
crypto_libbitcoin_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIC_FLAGS)
crypto_libbitcoin_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/hmac_sha256.cpp \
  crypto/rfc6979_hmac_sha256.cpp \
  crypto/hmac_sha512.cpp \
  crypto/scrypt.cpp \
  crypto/ripemd160.cpp \
  crypto/blake.c \
  crypto/bmw.c \
  crypto/groestl.c \
  crypto/jh.c \
  crypto/keccak.c \
  crypto/skein.c \
  crypto/common.h \
  crypto/sha256.h \
  crypto/sha3.h \
  crypto/sha3.cpp \
  crypto/sha512.h \
  crypto/siphash.cpp \
  crypto/siphash.h \
  crypto/hmac_sha256.h \
  crypto/rfc6979_hmac_sha256.h \
  crypto/hmac_sha512.h \
  crypto/scrypt.h \
  crypto/sha1.h \
  crypto/ripemd160.h \
  crypto/sph_blake.h \
  crypto/sph_bmw.h \
  crypto/sph_groestl.h \
  crypto/sph_jh.h \
  crypto/sph_keccak.h \
  crypto/sph_skein.h \
  crypto/sph_types.h


# common: shared between hud and tools
libbitcoin_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_common_a_SOURCES = \
  masternode/activemasternode.cpp \
  blockassembler.cpp \
  base58.cpp \
  bip38.cpp \
  state/finality.cpp \
  state/metrics.cpp \
  state/quorum.cpp \
  state/signaling.cpp \
  state/settlementdb.cpp \
  state/settlement_logic.cpp \
  state/settlement_builder.cpp \
  htlc/htlc.cpp \
  htlc/htlcdb.cpp \
  chainparams.cpp \
  consensus/upgrades.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/merkle.cpp \
  key_io.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  core_read.cpp \
  core_write.cpp \
  hash.cpp \
  key.cpp \
  keystore.cpp \
  messagesigner.cpp \
  net/netaddress.cpp \
  net/netbase.cpp \
  policy/feerate.cpp \
  protocol.cpp \
  pubkey.cpp \
  vrf.cpp \
  saltedhasher.cpp \
  scheduler.cpp \
  script/descriptor.cpp \
  script/btcstate.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/sign.cpp \
  script/standard.cpp \
  script/conditional.cpp \
  masternode/tiertwo_sync_state.cpp \
  warnings.cpp \
  script/script_error.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBSAPLING_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libbitcoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_util_a_SOURCES = \
  arith_uint256.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  logging.cpp \
  random.cpp \
  randomenv.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  support/lockedpool.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util/asmap.cpp \
  uint256.cpp \
  util/system.cpp \
  utilmoneystr.cpp \
  util/threadnames.cpp \
  utilstrencodings.cpp \
  util/string.cpp \
  util/validation.cpp \
  utiltime.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBSAPLING_H)

if GLIBC_BACK_COMPAT
libbitcoin_util_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)
endif

# sapling protocol primitives #
libsapling_a_CPPFLAGS = $(AM_CPPFLAGS) $(PIC_FLAGS) $(BITCOIN_INCLUDES)
libsapling_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsapling_a_SOURCES = \
  bech32.cpp \
  sapling/sapling_util.cpp \
  sapling/key_io_sapling.cpp \
  sapling/sapling_core_write.cpp \
  sapling/prf.cpp \
  sapling/noteencryption.cpp \
  sapling/address.cpp \
  sapling/note.cpp \
  sapling/zip32.cpp \
  sapling/crypter_sapling.cpp \
  sapling/saplingscriptpubkeyman.cpp \
  sapling/incrementalmerkletree.cpp \
  sapling/transaction_builder.cpp \
  sapling/sapling_operation.cpp

if GLIBC_BACK_COMPAT
libsapling_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)
endif

# cli: hu-cli
libbitcoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_cli_a_SOURCES = \
  rpc/client.cpp \
  $(BITCOIN_CORE_H) \
  $(LIBSAPLING_H)

nodist_libbitcoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# hud binary #
bathrond_SOURCES = bathrond.cpp
bathrond_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
bathrond_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
bathrond_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
bathrond_SOURCES += bathrond-res.rc
endif
bathrond_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBSAPLING) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBRUSTZCASH) \
  $(LIBZCASH_LIBS)

bathrond_LDADD += $(BOOST_LIBS) $(SQLITE3_LIBS) $(MINIUPNPC_LIBS) $(NATPMP_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)

# hu-cli binary #
bathron_cli_SOURCES = bathron-cli.cpp
bathron_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
bathron_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
bathron_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
bathron_cli_SOURCES += bathron-cli-res.rc
endif

bathron_cli_LDADD = \
  $(LIBBITCOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBSAPLING) \
  $(LIBRUSTZCASH) \
  $(LIBZCASH_LIBS)

bathron_cli_LDADD += $(BOOST_LIBS) $(EVENT_LIBS)
#

# hu-tx binary #
bathron_tx_SOURCES = bathron-tx.cpp
bathron_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
bathron_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
bathron_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
bathron_tx_SOURCES += bathron-tx-res.rc
endif

bathron_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBSECP256K1) \
  $(LIBSAPLING) \
  $(LIBRUSTZCASH) \
  $(LIBZCASH_LIBS)

bathron_tx_LDADD += $(BOOST_LIBS)
#

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/bitcoinconsensus.h
libbitcoinconsensus_la_SOURCES = \
  arith_uint256.cpp \
  primitives/transaction.cpp \
  crypto/hmac_sha512.cpp \
  crypto/scrypt.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  crypto/ripemd160.cpp \
  hash.cpp \
  pubkey.cpp \
  script/script.cpp \
  script/btcstate.cpp \
  script/interpreter.cpp \
  script/bitcoinconsensus.cpp \
  uint256.cpp \
  utilstrencodings.cpp

if GLIBC_BACK_COMPAT
  libbitcoinconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libbitcoinconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libbitcoinconsensus_la_LIBADD = $(LIBSECP256K1)
libbitcoinconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL
libbitcoinconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crc32c/src/*.gcda crc32c/src/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += masternode/*.gcda masternode/*.gcno
CLEANFILES += legacy/*.gcda legacy/*.gcno
CLEANFILES += hu/*.gcda hu/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += rpc/*.gcda rpc/*.gcno
CLEANFILES += sapling/*.gcda sapling/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += masternode/*.gcda masternode/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += util/*.gcda util/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

IMMER_DIST = immer

EXTRA_DIST = $(CTAES_DIST) rust
EXTRA_DIST += $(IMMER_DIST)


config/bathron-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/bathron-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/bathron-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/bathron-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__
	-rm -rf ../target

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
if TARGET_DARWIN
	@echo "Checking macOS dynamic libraries..."
	$(AM_V_at) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if TARGET_WINDOWS
	@echo "Checking Windows dynamic libraries..."
	$(AM_V_at) OBJDUMP=$(OBJDUMP) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) CPPFILT=$(CPPFILT) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) OBJDUMP=$(OBJDUMP) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

if EMBEDDED_LEVELDB
include Makefile.crc32c.include
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

# HU-Core: Qt/GUI completely removed - daemon only
