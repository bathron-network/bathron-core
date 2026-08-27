package=libevent
# 2.1.12-stable (amont) — REQUIS sur toute libc qui fournit arc4random SANS
# arc4random_addrandom (glibc >= 2.36). En 2.1.8 l'appel a arc4random_addrandom()
# dans evutil_rand.c n'est pas garde : la compilation echoue (GCC >= 14 traite la
# declaration implicite comme une erreur) et l'edition de liens echouerait de toute
# facon, le symbole etant absent de la glibc. La 2.1.12 amont garde l'appel :
#   evutil_rand.c:193
#   #if !defined(EVENT__HAVE_ARC4RANDOM) || defined(EVENT__HAVE_ARC4RANDOM_ADDRANDOM)
# Correction AMONT, aucun patch local. Garde de regression : src/test/libevent_version_tests.cpp
$(package)_version=2.1.12-stable
$(package)_download_path=https://github.com/libevent/libevent/archive/
$(package)_file_name=release-$($(package)_version).tar.gz
$(package)_sha256_hash=7180a979aaa7000e1264da484f712d403fcf7679b1e9212c4e3d09f5c93efc24

define $(package)_preprocess_cmds
  ./autogen.sh
endef

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --disable-openssl --disable-libevent-regress --disable-samples
  $(package)_config_opts += --disable-dependency-tracking --enable-option-checking
  $(package)_config_opts_release=--disable-debug-mode
  $(package)_config_opts_linux=--with-pic
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm lib/*.la
endef