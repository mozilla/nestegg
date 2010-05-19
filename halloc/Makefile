CFLAGS = -I. -ansi -Wall -pedantic

LIBNAME = libhalloc.a
OBJS    = src/halloc.o

$(LIBNAME): $(OBJS)
	ar rcs $(LIBNAME) $(OBJS)

install: $(LIBNAME)
	cp halloc.h /usr/include
	cp $(LIBNAME) /usr/lib

clean:
	rm -f $(LIBNAME) $(OBJS)
