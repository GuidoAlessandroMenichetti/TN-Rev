#include "custom_png.h"
#include "../common/structures.h"

PSP_MODULE_INFO("TNPopcornManager", 0x1000, 1, 1);

int use_custom_icon = 1; //*(3920)
SceUID peops_module = -1; //*3924
int no_pgd = 0; //*(12272)
unsigned unknownCode[3]; //12276
char path[64]; //12288
int (* forward_sub_000009A8)(SceModule2 * mod) = NULL; //*(12352)
void (* scePops_Manager_00000124)(int, void *, void *) = NULL; //*(12356)
int (* scePops_Manager_Unknown)(const char *, void *, int) = NULL; //*(12360)
t_config config; //12364

void patch_unknown() //loc_00000000
{
	_sb(0xFFFFFFFE, 0x49F40293);
	_sh(0x00000000, 0x49F40290);
};

int hook_sceIoOpen(const char * file_path, int flag, int mode) //loc_0000001C
{
	if((flag >> 30) & 1 == 0) //ext v0, a1, 30, 1
		return sceIoOpen(file_path, flag, mode);

	return sceIoOpen(file_path, flag & 0xBFFFFFFF, mode);
};

int hook_sceIoIoctl(SceUID fd, unsigned int cmd, void * indata, int inlen, void * outdata, int outlen) //loc_00000588
{
	if(cmd + 0xFBEFFFFF >= 2)
		return sceIoIoctl(fd, cmd, indata, inlen, outdata, outlen);
	else if(inlen == 4)
		sceIoLseek(fd, * indata, SEEK_SET);
	
	return 0;
};

void process_file() //sub_00000038
{
	//get file path and copy
	char * file_path = sceKernelInitFileName();
	strcpy(path, file_path);
	
	//destroy last '/'
	* strrchr(path, '/') = 0x0;
	
	//tries to open file
	SceUID fd = sceIoOpen(file_path, PSP_O_RDONLY, 0);
	if(fd >= 0)
	{
		//reads eboot header
		t_eboot_header header;
		sceIoRead(fd, &header, sizeof(t_eboot_header));
		
		//goes to psar offset
		sceIoLseek(fd, header.psar, SEEK_SET);
		
		//reads
		char pstitle[8];
		sceIoRead(fd, pstitle, 8);
		
		//defines offset to seek
		unsigned offset = header.psar + 0x400;
		if(!memcmp(pstitle, "PSTITLE", 7))
			offset = header.psar + 0x200;

		sceIoLseek(fd, offset, SEEK_SET);
		
		//reads magic
		unsigned magic; 
		sceIoRead(fd, &magic, sizeof(unsigned));
		
		if(magic != 0x44475000) //PGD magic
		{
			no_pgd = 1;
			
			//goes to icon offset
			sceIoLseek(fd, header.icon0, SEEK_SET);
			
			//gets png data
			unsigned png_data[6];
			sceIoRead(fd, png_data, sizeof(png_data));
			 
			//check if it has a valid icon0
			if(	png_data[0] == 0x474E5089 && png_data[1] == 0x0A1A0A0D && png_data[3] == 0x52444849 &&
				png_data[4] == 0x50000000 && png_data[5] == png_data[4])
				use_custom_icon = 0;
		};
		
		sceIoClose(fd);
	};
};

int stop_peops(int arg)
{
	if(arg - 7 >= 2)
	{
		if(sceKernelStopModule(peops_module, 0, 0, 0, 0) >= 0) //ModuleMgrForKernel_D1FF982A
			sceKernelUnloadModule(peops_module); //ModuleMgrForKernel_2E0911AA
	};
	
	return 0;
};

void load_peops_module(int arg0, int arg1, int arg2) //sub_0000022C
{
	SystemCtrlForKernel_E9773D1B(stop_peops);
	
	//sets options 
	SceKernelLMOption options;
	options.size = sizeof(SceKernelLMOption);
	options.mpidtext = 11;
	options.mpiddata = 11;
	options.flags = 0;
	options.position = 0;
	options.access = 1;
	options.creserved[0] = 0;
	options.creserved[1] = 0;
	
	//loads module
	SceUID ret = SystemCtrlForKernel_829E2C0D("/kd/peops.prx", 0, &options);
	peops_module = ret;
	
	if(ret >= 0)
		sceKernelStartModule(ret, 0, 0, 0, 0); //ModuleMgrForKernel_50F0C1EC
	
	sceKernelLoadModule(arg0, arg1, arg2); //ModuleMgrForKernel_977DE386
};

int hook_sceIoRead(SceUID fd, char * address, int size) //sub_00000424()
{
	//sets k1
	int k1 = pspSdkSetK1(0);
	
	//read bytes
	int bytes_read = sceIoRead(fd, address, size);
	
	//check all bytes specified in size were read
	if(bytes_read == size)
	{
		if(bytes_read == sizeof(custom_png))
		{
			unsigned png_magic = 0x474E5089;
			
			if(use_custom_icon && !memcmp(address, &png_magic, sizeof(unsigned)))
				memcpy(address, custom_png, sizeof(custom_png));
			else
			{
				if(address[1051] == 39 && address[1052] == 25 && address[1053] == 34 && address[1054] == 65 && address[1050] == address[1055])
					address[1051] = 85;
			};
		}
		else if(bytes_read == 4)
		{
			unsigned elf_magic = 0x464C457F;

			if(!memcmp(address, &elf_magic, sizeof(unsigned)))
			{
				unsigned psp_header = 0x5053507E;
				memcpy(address, &psp_header, sizeof(unsigned));
			};
		}
		else if(bytes_read >= 1056)
		{
			if(address[1051] == 39 && address[1052] == 25 && address[1053] == 34 && address[1054] == 65 && address[1050] == address[1055])
				address[1051] = 85;
		};
	};
	
	//restores k1
	pspSdkSetK1(k1);
	
	return bytes_read;
};

int read_bytes(const char * file_path, void * address, int size) //sub_000001C0
{
	SceUID fd = sceIoOpen(file_path, PSP_O_RDONLY, 0);
	
	if(fd < 0)
		return fd;
		
	int bytes_read = sceIoRead(fd, address, size);
	sceIoClose(fd);
	
	return bytes_read;
};

int write_bytes(const char * file_path, void * address, int size) //sub_000005E0
{
	SceUID fd = sceIoOpen(file_path, PSP_O_CREAT | PSP_O_TRUNC | PSP_O_WRONLY, 0777);
	
	if(fd < 0)
		return fd;
		
	int bytes_wrote = sceIoWrite(fd, address, size);
	sceIoClose(fd);
	
	return bytes_wrote;
};

int read_keys(const char * file_path, void * address, int arg2) //sub_0000064C
{
	char keys_path[64];
	sprintf(keys_path, "%s/KEYS.BIN", path);
	
	if(read_bytes(keys_path, address, 16) == 16)
	{
		scePops_Manager_00000124(16, address, address);
		return 0;
	};
		
	//tries to open file
	SceUID fd = sceIoOpen(file_path, PSP_O_RDONLY, 0);
	if(fd >= 0)
	{
		//reads eboot header
		t_eboot_header header; //sp + 4
		sceIoRead(fd, &header, sizeof(t_eboot_header));
		
		//seeks to pspdat
		sceIoLseek(fd, header.pspdat, SEEK_SET);
		
		//reads magic
		unsigned magic;
		sceIoRead(fd, &magic, sizeof(unsigned));
		sceIoClose(fd);
		
		if(magic == 0x464C457F) //elf magic
		{
			memset(address, 'X', 16);
			return fd;
		};
	};
	
	//creates keys?
	int ret = scePops_Manager_Unknown(file_path, address, arg2);

	//stores keys
	if(ret >= 0)
		write_bytes(keys_path, address, 16);
	
	return ret;
};

void flush_cache() //sub_00000798
{
	sceKernelDcacheWritebackAll();
	sceKernelIcacheClearAll(); //LoadCoreForKernel_D8779AC6();
};

void * sub_00000334(int arg)
{
	char partition_name[4] = {0x0, 0x0, 0x0, 0x0}; //3640
	
	SceUID block = sceKernelAllocPartitionMemory(2, partition_name, 0, 8, 0); //SysMemForKernel_237DBD4F(2, 3640, 0, 8, 0);
	unsigned * data = sceKernelGetBlockHeadAddr(block); //SysMemForKernel_9D9A5BA1(v0); 

	data[0] = 0x03E00008;
	data[1] = (sceKernelQuerySystemCall(arg) << 6) | 0x000C; //InterruptManagerForKernel_8B61808B

	return data;
}

int PopcornPrivate_E4AB06A1(int arg0, void * arg1, void * arg2)
{
	//set k1
	int k1 = pspSdkSetK1(0);
	
	//decompress
	int ret = sceKernelDeflateDecompress(arg2, arg0, arg1, 0);
	
	if(ret ^ 0x9300 == 0)
		ret = 0x92FF;
		
	//restore k1
	pspSdkSetK1(k1);

	return ret;
};

int sub_000009A8(SceModule2 * mod)
{
	if(!strcmp(mod->modname, "pops"))
	{
		_sw(MAKE_CALL(sub_00000334(PopcornPrivate_E4AB06A1)), mod->text_addr + 0xDB78);
		_sw(0x00000000, mod->text_addr + 0x25254);
		
		if(use_custom_icon)
			_sw(0x2405208F, mod->text_addr + 0x36D50);
		
		flush_cache();
	};
	
	if(forward_sub_000009A8)
		return forward_sub_000009A8(mod);
		
	return 0;
};

int module_start()
{
	//loads config
	sctrlSEGetConfig(&config); //SystemCtrlForKernel_16C3B7EE
	
	process_file();
	
	//searches for pops module
	SceModule2 * mod = sceKernelFindModuleByName("scePops_Manager"); //LoadCoreForKernel_CF8A41B1
	
	if(no_pgd)
	{			
		_sw(MAKE_STH(hook_sceIoOpen), mod->text_addr + 0x3B9C);
		_sw(MAKE_STH(hook_sceIoIoctl), mod->text_addr + 0x3BAC);
		_sw(MAKE_STH(hook_sceIoRead), mod->text_addr + 0x3BB4);
		_sw(0x00000000, mod->text_addr + 0x564);
		_sw(0x03E00008, mod->text_addr + 0xA28);
		_sw(0x24020001, mod->text_addr + 0xA2C);
		_sw(0x03E00008, mod->text_addr + 0xAB8);
		_sw(0x24020001, mod->text_addr + 0xABC);
		_sw(0x03E00008, mod->text_addr + 0xEAC);
		_sw(0x00001021, mod->text_addr + 0xEB0);
		_sw(0x00000000, mod->text_addr + 0x1E80);
		
		forward_sub_000009A8 = (void *) sctrlHENSetStartModuleHandler(sub_000009A8); //SystemCtrlForKernel_1C90BECB
	};
	
	unknownCode[0] = _lw(mod->text_addr + 0x266C); //12276
	unknownCode[1] = MAKE_JUMP(mod->text_addr + 0x2674); //12280
	unknownCode[2] = _lw(mod->text_addr + 0x2670); //12284
		
	scePops_Manager_00000124 = (void *)(mod->text_addr + 0x124);
	scePops_Manager_Unknown = (void *) unknownCode;
	
	_sw(MAKE_JUMP(read_keys), mod->text_addr + 0x266C);
	_sw(0x00000000, mod->text_addr + 0x2670);
	_sw(0x00002021, mod->text_addr + 0x2DCC);
	_sw(0x00001021, mod->text_addr + 0x2DD0);
	_sw(0x03E00008, mod->text_addr + 0x33B4);
	_sw(0x00001021, mod->text_addr + 0x33B8);
	_sw(0x03E00008, mod->text_addr + 0x342C);
	_sw(0x00001021, mod->text_addr + 0x3430);
	_sw(0x03E00008, mod->text_addr + 0x3490);
	_sw(0x00001021, mod->text_addr + 0x3494);
	_sw(0x03E00008, mod->text_addr + 0x3590);
	_sw(0x00001021, mod->text_addr + 0x3594);
	_sw(0x03E00008, mod->text_addr + 0x35AC);
	_sw(0x00001021, mod->text_addr + 0x35B0);
	_sw(MAKE_JUMP(patch_unknown), mod->text_addr + 0x3514);
	_sw(0x00000000, mod->text_addr + 0x3518);

	//patch to load peops module
	if(config.use_peops)
		_sw(MAKE_CALL(load_peops_module), mod->text_addr + 0x1EE0);
	
	//clears cache
	flush_cache();
	return 0;
};