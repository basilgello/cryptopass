TESTS = testbase64 testfastpbkdf2 testlibcryptopass

check_PROGRAMS = testbase64 testfastpbkdf2 testlibcryptopass

testbase64_SOURCES = base64/testbase64.c
testbase64_LDADD = ../lib/libcryptopass.a
testbase64_CPPFLAGS = -I../lib/ $(CPPFLAGS)

testfastpbkdf2_SOURCES = fastpbkdf2/testfastpbkdf2.c
testfastpbkdf2_LDADD = ../lib/libcryptopass.a
testfastpbkdf2_CPPFLAGS = -I ../lib/ $(CPPFLAGS)

testlibcryptopass_SOURCES = libcryptopass/testlibcryptopass.c
testlibcryptopass_LDADD = ../lib/libcryptopass.a
testlibcryptopass_CPPFLAGS = -I ../lib/ $(CPPFLAGS)
