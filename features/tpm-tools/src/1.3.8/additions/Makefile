# LDFLAGS = -L$PREFIX/lib
# CFLAGS = -I$PREFIX/include
TPM_TOOLS_SRC ?= ../../../target/tpm-tools-1.3.8-patched
SAFESTRING = ../../../../SafeStringLibrary
CFLAGS += -g -O0 -DLOCALEDIR='"/usr/share/locale"'
CFLAGS += -I$(TPM_TOOLS_SRC) -I$(TPM_TOOLS_SRC)/include -I$(SAFESTRING)/include
CFLAGS += -fstack-protector-strong -fPIE -fPIC -O2 -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
LDFLAGS += -L$(SAFESTRING)
LDFLAGS += -z noexecstack -z relro -z now -pie
TPM_TOOLS_SRC_FILES = $(TPM_TOOLS_SRC)/lib/tpm_tspi.c $(TPM_TOOLS_SRC)/lib/tpm_utils.c $(TPM_TOOLS_SRC)/lib/tpm_log.c

all: tpm_createkey tpm_bindaeskey tpm_unbindaeskey tpm_signdata

tpm_createkey:
	gcc $(LDFLAGS) $(CFLAGS) -o tpm_createkey tpm_createkey.c $(TPM_TOOLS_SRC_FILES) -lcrypto -ltspi -lSafeStringRelease

tpm_bindaeskey:
	gcc $(LDFLAGS) $(CFLAGS) -o tpm_bindaeskey tpm_bindaeskey.c $(TPM_TOOLS_SRC_FILES) -lcrypto -ltspi -lSafeStringRelease

tpm_unbindaeskey:
	gcc $(LDFLAGS) $(CFLAGS) -o tpm_unbindaeskey tpm_unbindaeskey.c $(TPM_TOOLS_SRC_FILES) -lcrypto -ltspi -lSafeStringRelease

tpm_signdata:
	gcc $(LDFLAGS) $(CFLAGS) -o tpm_signdata  tpm_signdata.c $(TPM_TOOLS_SRC_FILES) -lcrypto -ltspi -lSafeStringRelease

install: tpm_createkey tpm_bindaeskey tpm_unbindaeskey tpm_signdata
	mkdir -p $(PREFIX)/bin
	cp tpm_createkey tpm_bindaeskey tpm_unbindaeskey tpm_signdata $(PREFIX)/bin
