#include "lib.h"

void memset(unsigned char * destination, unsigned char value, unsigned size) //sub_00010F74
{
	while(size)
	{
		* destination = value;
		size--;
		destination++;
	};
};

void memcpy(unsigned char * destination, const unsigned char * source, int size) //sub_00010F48
{
	while(size > 0)
	{
		* destination = * source;
		destination++;
		source++;
		size--;
	};
};

int ValidUserAddress(void * addr)
{
	if((u32)addr >= 0x08800000 && (u32)addr < 0x0A000000) 
		return 1;
		
	return 0;
}

unsigned FindImport(char * libname, unsigned nid) //sub_00010DB8
{
	u32 i;
	for(i = 0x08800000; i < 0x0A000000; i += 4)
	{
		SceLibraryStubTable *stub = (SceLibraryStubTable *)i;

		if((stub->libname != libname) && ValidUserAddress((void *)stub->libname) && ValidUserAddress(stub->nidtable) && ValidUserAddress(stub->stubtable))
		{
			if(strcmp(libname, stub->libname) == 0)
			{
				u32 *nids = stub->nidtable;

				int count;
				for(count = 0; count < stub->stubcount; count++)
				{
					if(nids[count] == nid)
					{
						return ((u32)stub->stubtable + (count * 8));
					}
				}
			}
		}
	}

	return 0;
}

int strlen(const char * str) //sub_00010E94
{
	int c = 0;
	while(* str)
	{
		str++;
		c++;
	};
	
	return c;
};

int strcmp(const char *s1, const char *s2) //sub_00010F14
{
	int val = 0;
	const unsigned char *u1, *u2;

	u1 = (unsigned char *) s1;
	u2 = (unsigned char *) s2;

	while(1)
	{
		if(*u1 != *u2)
		{
			val = (int) *u1 - (int) *u2;
			break;
		}

		if((*u1 == 0) && (*u2 == 0))
		{
			break;
		}

		u1++;
		u2++;
	}

	return val;
}

u32 FindTextAddrByName(const char *modulename)
{
	u32 kaddr;
	for (kaddr = 0x88000000; kaddr < 0x88400000; kaddr += 4) {
		if (strcmp((const char *)kaddr, modulename) == 0) {
			if ((*(u32*)(kaddr + 0x64) == *(u32*)(kaddr + 0x78)) && \
				(*(u32*)(kaddr + 0x68) == *(u32*)(kaddr + 0x88))) {
				if (*(u32*)(kaddr + 0x64) && *(u32*)(kaddr + 0x68))
					return *(u32*)(kaddr + 0x64);
			}
		}
	}
	return 0;
}

unsigned FindFunction(const char * modulename, const char * library, unsigned nid) //sub_00010CCC
{
	u32 addr = FindTextAddrByName(modulename);

	if (addr) {
		for (; addr < 0x88400000; addr += 4) {
			if (strcmp(library, (const char *)addr) == 0) {
				u32 libaddr = addr;

				while (*(u32*)addr != libaddr)
					addr -= 4;

				u16 imports = *(u16*)(addr + 10);
				u32 jump = (u32)imports * 4;

				addr = *(u32*)(addr + 12);

				while (imports--) {
					if (*(u32*)addr == nid)
						return *(u32*)(addr + jump);

					addr += 4;
				}
			}
		}
	}

	return 0;
}
