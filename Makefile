CFLAGS =  -DMLX_WITH_LIBDW -I/home/mark/myResearch/elfutils-0.165/ARM_LIBS/include/elfutils -I/home/mark/myResearch/elfutils-0.165/ARM_LIBS/include -g -O2 -Wall -I/home/mark/myResearch/libunwind/LIBUNWIND_ARM/include 
LDLIBS =  -L/home/mark/myResearch/libunwind/LIBUNWIND_ARM/lib -L/home/mark/myResearch/elfutils-0.165/ARM_LIBS/lib -L/home/mark/myResearch/elfutils-0.165/ARM_LIBS/lib/elfutils -L/home/mark/nfs/ARM_LIBS/lib -lunwind-ptrace -lunwind -lunwind-arm -ldw -lelf -lz -pthread 
#CFLAGS =  -DRPI -DMLX_WITH_LIBDW -I/usr/include/elfutils/ -g -O2 -Wall 
#LDLIBS =  -lunwind-ptrace -lunwind -lunwind-arm -ldw -lelf -lz 
LDFLAGS = 
PREFIX = /usr
DESTDIR =
CC = arm-linux-gnueabihf-gcc
CXX = arm-linux-gnueabihf-g++
TARGET = memtrace
TARGET2 = test
TARGET3 = elf_parser

SOURCES = breakpoint.c debug_file.c debug_line.c proc_info.c symtab.c ptrace_utils.c 
OBJS = breakpoint.o debug_file.o debug_line.o proc_info.o symtab.o ptrace_utils.o

all: $(TARGET) $(TARGET2) $(TARGET3) 

$(TARGET) : $(OBJS) memtrace.c
	 $(CC) -g -c memtrace.c $(CFLAGS)
	 $(CC) -g -static -o memtrace memtrace.o $(OBJS) $(LDLIBS)
	 cp $(TARGET) ~/nfs/ && sync

$(TARGET2) : test.o
	$(CC) -g -o test test.c

$(TARGET3) : elf_parser.o
	$(CC) -g -c elf_parser.c $(CFLAGS) 
	$(CC) -g -o elf_parser elf_parser.o $(LDLIBS)
	cp $(TARGET3) ~/nfs/ && sync

clean :
	rm -f *.o $(TARGET) $(TARGET2) $(TARGET3)

install :
	mkdir -p $(DESTDIR)$(PREFIX)/bin/
	install $(TARGET) $(DESTDIR)$(PREFIX)/bin/
uninstall :
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

breakpoint.o: breakpoint.c hash.h list.h \
	 breakpoint.h ptrace_utils.h symtab.h minigdb.h
debug_file.o: debug_file.c debug_file.h minigdb.h
debug_line.o: debug_line.c debug_line.h array.h minigdb.h proc_info.h \
 debug_file.h /usr/include/elfutils/libdw.h
proc_info.o: proc_info.c proc_info.h
symtab.o: symtab.c array.h minigdb.h proc_info.h debug_file.h
ptrace_utils.o: ptrace_utils.c ptrace_utils.h
