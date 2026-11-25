AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(srcdir)/include -I$(srcdir)/src

if USE_APPLE_EXPLORER
noinst_LIBRARIES = libappleexplorer.a
libappleexplorer_a_SOURCES = \
	include/apple_explorer.h \
	src/aex_internal.h \
	src/crypto_compress.c \
	src/container.c \
	src/fs_hfs.c \
	src/fs_apfs.c
endif

EXTRA_DIST = \
	LICENSE \
	README.md \
	include/apple_explorer.h \
	src/aex_internal.h \
	src/crypto_compress.c \
	src/container.c \
	src/fs_hfs.c \
	src/fs_apfs.c
