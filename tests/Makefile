ifndef LIBDIR
LIBDIR = ..
endif
ifndef LIB
LIB = $(LIBDIR)/libencoding.a
endif

all:	test_decode
	$(CURDIR)/test_decode

test_decode:	test_decode.o $(LIB)
	$(CC) $(CCFLAGS) -o $@ $^

clean:
	rm -f test_decode *.o

%.o: %.c
	$(CC) $(CCFLAGS) -I$(LIBDIR) -c $<
