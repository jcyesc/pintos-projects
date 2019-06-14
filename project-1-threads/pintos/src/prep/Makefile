all: test_mem listtest listordered

LIBDIR=../lib
KERNELDIR=$(LIBDIR)/kernel
SOURCES=memalloc.c $(KERNELDIR)/list.c
SOURCES1=test_mem.c $(SOURCES)
SOURCES2=listtest.c $(KERNELDIR)/list.c $(LIBDIR)/string.c
SOURCES3=listordered.c $(KERNELDIR)/list.c $(LIBDIR)/string.c
SOURCES4=sizes.c $(KERNELDIR)/list.c $(LIBDIR)/string.c

all: test_mem listtest

test_mem: $(SOURCES1)
	$(CC) -g -Wall -I$(LIBDIR) -I$(KERNELDIR) -o $@ $(SOURCES1) -lpthread
	#$(CC) -m32 -g -I$(LIBDIR) -I$(KERNELDIR) -o $@ $(SOURCES1) -lpthread

listtest: $(SOURCES2)
	$(CC) -g -Wall -I$(LIBDIR) -I$(KERNELDIR) -o $@ $(SOURCES2) -lpthread

listordered: $(SOURCES3)
	$(CC) -g -Wall -I$(LIBDIR) -I$(KERNELDIR) -o $@ $(SOURCES3) -lpthread

sizes: $(SOURCES4)
	$(CC) -g -Wall -I$(LIBDIR) -I$(KERNELDIR) -o $@ $(SOURCES4) -lpthread

clean:
	/bin/rm -rf test_mem listtest listordered *.o *.dSYM
