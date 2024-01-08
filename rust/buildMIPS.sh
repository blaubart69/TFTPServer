#!/bin/sh
PATH=$PATH:~/dev/sdk/openwrt-sdk-21.02.3-ath79-tiny_gcc-8.4.0_musl.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-8.4.0_musl/bin
STAGING_DIR=~/dev/sdk/openwrt-sdk-21.02.3-ath79-tiny_gcc-8.4.0_musl.Linux-x86_64/staging_dir

cargo +nightly build --profile minsize --target mips-unknown-linux-musl \
  -Z build-std="panic_abort,std,core,alloc"     \
  -Z build-std-features="panic_immediate_abort"

