TESTS = testbase64 testfastpbkdf2

check_PROGRAMS = testbase64 testfastpbkdf2

testbase64_SOURCES = base64/testbase64.c ../lib/base64/base64.c
testbase64_CPPFLAGS = -I../lib/ $(CPPFLAGS)

testfastpbkdf2_SOURCES = fastpbkdf2/testfastpbkdf2.c ../lib/fastpbkdf2/fastpbkdf2.c
testfastpbkdf2_CPPFLAGS = -DFASTPBKDF2_NOASM -I ../lib/ $(CPPFLAGS)
