CPPFLAGS = -I. -Ihalloc
CFLAGS = -ansi -pedantic -Wall -Wextra -Wno-long-long
CFLAGS += -O0 -g
#CFLAGS += -Wstrict-prototypes -Wpointer-arith -Wshadow -Wcast-qual -Wmissing-prototypes
#CFLAGS += -Wstrict-overflow=5 -Wredundant-decls -Wreturn-type

test: test.o src/nestegg.o halloc/src/halloc.o

test.o: test.c nestegg/nestegg.h
src/nestegg.o: nestegg/nestegg.h src/nestegg.c halloc/halloc.h
halloc/src/halloc.o: halloc/src/halloc.c halloc/halloc.h halloc/src/align.h halloc/src/hlist.h halloc/src/macros.h

clean:
	rm -f test test.o src/*.o halloc/src/*.o

.PHONY: clean
