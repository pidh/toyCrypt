# 
#  Copyright 2011-2013 pidh <github360@yahoo.co.jp>. All rights reserved.
# 
# Usage of the works is permitted provided that this instrument is retained
# with the works, so that any entity that uses the works is notified of
# this instrument.
#
# DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
# 
TARGETS=test_aes test_sha1 test_sha256 test_hmac_sha256

all: $(TARGETS)

test_aes: test_aes.o aes.o
	$(CC) -o $@ $^

test_sha1: test_sha1.o sha1.o
	$(CC) -o $@ $^

test_sha256: test_sha256.o sha256.o
	$(CC) -o $@ $^

test_hmac_sha256: test_hmac_sha256.o hmac_sha256.o sha256.o
	$(CC) -o $@ $^

aes.o: aes.c aes.h comtypes.h
test_aes.o: test_aes.c aes.h comtypes.h

sha1.o: sha1.c sha1.h comtypes.h
test_sha1.o: test_sha1.c sha1.h comtypes.h

sha256.o: sha256.c sha256.h comtypes.h
test_sha256.o: test_sha256.c sha256.h comtypes.h

hmac_sha256.o: hmac_sha256.c sha256.h comtypes.h
test_hmac_sha256.o: test_hmac_sha256.c sha256.h comtypes.h

clean:
	-rm -f *.o $(TARGETS)
