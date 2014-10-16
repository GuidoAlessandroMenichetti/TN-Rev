#ifndef COMMON_H
#define COMMON_H

//taken from uOFW
typedef struct
{
	u32 size;
	u32 flags;
	char str8[16];
	char str24[11];
	int unk36;
	char qtgp2[8];
	char qtgp3[16];
	u32 allowReplaceUmd;
	char gameId[14];
	u32 unk84;
	char str88[8];
	u32 umdCacheOn;
	u32 sdkVersion;
	u32 compilerVersion;
	u32 dnas;
	u32 unk112;
	char str116[64];
	char str180[11];
	char str196[8];
	char unk204[8];
	int unk212;
	int unk216;
} SceKernelGameInfo;

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
} __attribute__ ((__packed__)) packet_entry;

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