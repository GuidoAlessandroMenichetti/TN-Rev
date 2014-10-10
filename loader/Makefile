PSPSDK=$(shell psp-config --pspsdk-path)
PSPDEV=$(shell psp-config --pspdev-path)
INCLUDE=$(PSPSDK)/include

CC = psp-gcc
CFLAGS := -D PSP -I $(INCLUDE) -W -Wall -O2 -G0 -fno-pic -mno-abicalls -w -fomit-frame-pointer
ASM = psp-as

all: main.o lib.o linker.x
	$(PSPDEV)/bin/psp-ld -T linker.x -L$(PSPSDK)/lib main.o lib.o -o main.elf
	$(PSPDEV)/bin/psp-strip -s main.elf
	$(PSPDEV)/bin/psp-objcopy -O binary main.elf TN.BIN

lib.o: ../common/lib.c
	$(CC) $(CFLAGS) -S ../common/lib.c -o lib.s
	$(ASM) lib.s -o lib.o
	
main.o: main.c
	$(CC) $(CFLAGS) -S main.c -o main.s
	$(ASM) main.s -o main.o
	
clean:
	rm *.bin *.o