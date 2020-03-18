#!/bin/bash
VERSION=1.0
LIBKMIP_DIR=c

# PREFIX must be an absolute path
# PREFIX must be exported for "make" subshell
export PREFIX=${PREFIX:-/usr/local/lib}
export LINUX_TARGET=${LINUX_TARGET:-generic}
export CFLAGS="-fstack-protector-strong -fPIE -fPIC -O2 -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security"
export LDFLAGS="-z noexecstack -z relro -z now -pie"


install_libkmip() {
  echo "PREFIX=$PREFIX"
  mkdir -p $PREFIX
  if [ -d "$LIBKMIP_DIR" ]; then
    (cd $LIBKMIP_DIR && CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" ${KWFLAGS_LIBKMIP} make)
    if [ $? -ne 0 ]; then echo "Failed to make libkmip"; exit 1; fi
    (cd $LIBKMIP_DIR && CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}" make install)
    if [ $? -ne 0 ]; then echo "Failed to make install libkmip"; exit 2; fi
  fi
}

install_libkmip
rm -rf dist-clean
mkdir dist-clean
cp -r $PREFIX dist-clean
