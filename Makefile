SRC = decode.c
LIBDIR = $(CURDIR)
LIB = $(LIBDIR)/libencoding.a
OBJ = $(SRC:.c=.o)
CCFLAGS  = -g -Wall -Wextra -pedantic
ifdef DEBUG
CCFLAGS += -O0
else
CCFLAGS += -O3 -DNDEBUG
endif

export LIB LIBDIR CCFLAGS

all:	$(LIB)

$(LIB):	$(OBJ)
	$(AR) $(ARFLAGS) $@ $^

test:	$(LIB)
	$(MAKE) -C tests

clean:
	rm -f *.o $(LIB)
	$(MAKE) -C tests clean

%.o: %.c %.h
	$(CC) $(CCFLAGS) -c $<
