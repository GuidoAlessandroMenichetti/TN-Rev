#ifndef COMMON_H
#define COMMON_H

#define MAKE_STH(f)  ((((unsigned)(f) & 0x0FFFFFFC) >> 2) | 0x08000000)
#define MAKE_STH2(f) ((((unsigned)(f) & 0xF3FFFFFF) << 2) | 0x80000000) 
#define MAKE_JUMP(f) ((((unsigned)(f) >> 2) & 0x03FFFFFFF) | 0x08000000)
#define MAKE_CALL(f) ((((unsigned)(f) >> 2) & 0x03FFFFFFF) | 0x0C000000) 

typedef struct s_kernel_file
{
	char * name;
	void * buffer;
	unsigned size;
} kernel_file;

typedef struct s_packet_entry
{
	unsigned magic;
	unsigned data_size;
	unsigned name_size;
	//name
	//data
} packet_entry;

typedef struct
{
	unsigned unknown1;
	unsigned unknown2;
	unsigned unknown3;
	unsigned unknown4;
	unsigned unknown5;
	unsigned unknown6;
	unsigned load_eboot;
	unsigned unknown8;
	unsigned unknown9;
	unsigned unknown10;
	unsigned unknown11;
	unsigned unknown12;
	unsigned unknown13;
	unsigned unknown14;
	unsigned unknown15;
	unsigned unknown16;
	unsigned unknown17;
	unsigned unknown18;
	unsigned unknown19;
	unsigned unknown20;
	unsigned unknown21;
	unsigned unknown22;
	unsigned unknown23;
	unsigned unknown24;
	unsigned unknown25;
	unsigned unknown26;
	unsigned unknown27;
	unsigned unknown28;
	unsigned unknown29;
	unsigned unknown30;
	unsigned unknown31;
	unsigned unknown32;
	unsigned unknown33;
	unsigned unknown34;
	unsigned unknown35;
	unsigned unknown36;
	unsigned unknown37;
	unsigned unknown38;
	unsigned unknown39;
	unsigned unknown40;
	unsigned unknown41;
} t_config; //size 164

#endif