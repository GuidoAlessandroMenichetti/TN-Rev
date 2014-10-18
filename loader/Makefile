TARGET = TN
OBJS = main.o ../common/lib.o

CC = psp-gcc
AS = psp-as

INCDIR = ../include
CFLAGS = -O2 -G0 -Wall -fno-pic -I../include -I$(shell psp-config --pspsdk-path)/include

all: $(TARGET).BIN

%.BIN: %.elf
	psp-strip -s -O binary $< -o $@

$(TARGET).elf: $(OBJS)
	psp-ld -nostartfiles -T linker.x -nostdlib $^ -o $@

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).BIN
