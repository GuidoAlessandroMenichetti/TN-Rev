//tn-v loader full reverse by gbot

#include "reboot.h"
#include "../common/lib.h"
#include "../common/structures.h"

typedef struct
{
	char game_id[14];
	char exploit_path[66];
	int fw_version;
	int reboot_size;
	char unknown_big[408];
	char unknown_not_used[68];
	int load_mode; 
	char unknown_not_used2[28]; 
} __attribute__((__packed__)) t_globals; //size 596

static void (* _sceKernelDcacheWritebackInvalidateAll)() = (void *) 0x88000744; 
static void (* _sceKernelIcacheInvalidateAll)() = (void *) 0x88000E98;
static SceKernelGameInfo * (* _sceKernelGetGameInfo)() = (void *) 0x880098A4;
static char * (* _sprintf)(char * destination, const char * mask, ...) = (void *) 0x8800E1D4;
static unsigned (* _sceKernelGzipDecompress)(unsigned, int, void *, int) = (void *) 0x8800F804;

SceUID (* _sceIoOpen)(const char *, int, int);
int (* _sceIoRead)(SceUID, void *, unsigned);
int (* _sceIoWrite)(SceUID, const void *, unsigned);
int (* _sceIoClose)(SceUID);
int (* _sceIoGetstat)(const char *, SceIoStat *);

SceModule2 * (* _sceKernelFindModuleByName)(const char *);
int (* _sceReboot)(void *, void *, int, int);
int (* _LoadExec000029C0)(int); 

t_globals globals;
static char vshmain_args[0x400]; 

//#define DEBUG
#ifdef DEBUG

void _log_create()
{
	char buffer[0x100];
	_sprintf(buffer, "%s/LOG.TXT", globals.exploit_path);
	SceUID fd = _sceIoOpen(buffer, PSP_O_CREAT | PSP_O_WRONLY | PSP_O_TRUNC, 0777); 
	_sceIoClose(fd);
};

void _log(const char * str)
{
	char buffer[0x100];
	_sprintf(buffer, "%s/LOG.TXT", globals.exploit_path);
	SceUID fd = _sceIoOpen(buffer, PSP_O_CREAT | PSP_O_WRONLY | PSP_O_APPEND, 0777);
	_sprintf(buffer, str);
	_sceIoWrite(fd, buffer, _strlen(buffer));
	_sceIoClose(fd);
};

#endif

void fill_screen(unsigned color)
{
	unsigned pixel;
	for(pixel = 0x44000000; pixel < 0x44180000; pixel += 4)
		*(unsigned *)pixel = color;
};

void error()
{
	//fills screen red
	fill_screen(0x000000FF);
	
	//stop the system
	__asm("break 0x0");
};

int load_config(t_config * data)
{
	#ifdef DEBUG
	_log("Loading config from ms0:/flash/config.tn.\n");
	#endif

	//fills config structure with 0's
	_memset(data, 0, sizeof(t_config));
	
	//tries to open config file
	SceUID fd = _sceIoOpen("ms0:/flash/config.tn", PSP_O_RDONLY, 0);
	if(fd < 0)
		return fd;
	
	//reads bytes
	int bytes_read = _sceIoRead(fd, data, sizeof(t_config));
	int ret = bytes_read;
	
	//didnt read the correct amount of bytes
	if(bytes_read != sizeof(t_config))
	{
		//fills with 0's again
		_memset(data, 0x0, sizeof(t_config));
		ret = -1;
	};
	
	//closes file
	_sceIoClose(fd);
	
	#ifdef DEBUG
	if(ret != -1)
		_log("Config successfully loaded\n");
	#endif

	return ret;
};

int get_fw_version()
{
	#ifdef DEBUG
	_log("Getting fw version\n");
	#endif

	fill_screen(0x00999999); //grey	
	
	//searches savedata_auto_dialog.prx module file entry
	kernel_file * file = (kernel_file *) 0x8B000000;
	while(file->buffer)
	{
		if(!_strcmp(file->name, "/vsh/module/savedata_auto_dialog.prx"))
		{
			//savedata_auto_dialog size changed in every fw due to patches
			switch(file->size)
			{
				case 0xBB80: return 0x160; //fw 1.60
				case 0xBC00: return 0x165; //fw 1.65
				case 0xBD00: return 0x169; //fw 1.69
				case 0xBD40: return 0x180; //fw 1.80
				case 0xBE40: return 0x200; //fw 2.00
				case 0xBEC0: return 0x205; //fw 2.05
				case 0xBF40: return 0x210; //fw 2.10
				case 0xC080: return 0x260; //fw 2.60
				case 0xC200: return 0x261; //fw 2.61
				case 0xC800: return 0x300; //fw 3.00
				case 0xCC40: return 0x301; //fw 3.01
				case 0xB6C0: return 0x310; //fw 3.10
				case 0xB740: return 0x315; //fw 3.15
				case 0xBE00: return 0x318; //fw 3.18
				case 0xBF00: return 0x330; //fw 3.30
			};
			
			//unknown firmware, cant continue :(
			
			//creates string with the size
			char size_string[64];
			_sprintf(size_string, "size: 0x%08X\n", file->size);

			//builds output path
			char size_path[64];
			_sprintf(size_path, "%s/size.txt", globals.exploit_path); 
			SceUID fd = _sceIoOpen(size_path, PSP_O_CREAT | PSP_O_WRONLY | PSP_O_TRUNC, 0777);

			//saves string to a file in exploit_path
			_sceIoWrite(fd, size_string, _strlen(size_string));
			_sceIoClose(fd);
			
			//fills screen with blue
			fill_screen(0x00FF0000);
			
			#ifdef DEBUG
			_log("Unknown firmware, stopping\n");
			#endif
			
			//stops the system
			__asm("break 0x0");
		};
		
		file++;
	};

	//couldn't find savedata_auto_dialog
	error();
	return 0xFFFFFFFF;
};

int load_packet_files()
{
	fill_screen(0x0000FFFF); //yellow

	//builds packet file path
	char packet_file[64];
	_sprintf(packet_file, "%s/FLASH0.TN", globals.exploit_path);
	
	#ifdef DEBUG
	_log("Loading packet from ");
	_log(packet_file);
	_log("\n");
	#endif
	
	//tries to open packet
	SceUID fd = _sceIoOpen(packet_file, PSP_O_RDONLY, 0);
	if(fd < 0)
		return fd;
		
	//reads file count inside package
	unsigned packet_file_count = 0;
	_sceIoRead(fd, &packet_file_count, sizeof(unsigned));
	
	//counts amount and bytes of module info structures already in flash
	int k_files_bytes = 0; 
	int k_files_count = 0;
	kernel_file * file = (kernel_file *) 0x8B000000;
	while(file->buffer)
	{
		k_files_count++;
		k_files_bytes += sizeof(kernel_file);
		file++;
	};
	
	//copies those modules info to a higher address
	_memcpy((void *)(0x8BA00000 + packet_file_count * sizeof(kernel_file)), (void *) 0x8B000000, k_files_bytes);

	//nulls buffer of last entry
	file = (kernel_file *)(0x8BA00000 + (k_files_count + packet_file_count) * sizeof(kernel_file));
	file->buffer = 0x0;
	
	int bytes_read;
	packet_entry entry;
	
	//pointers to add new kernel module files
	kernel_file * new_file = (kernel_file *) 0x8BA00000;
	char * new_name = (char *) 0x8BE00000;
	char * new_data = (char *)(0x8BA00000 + (k_files_count + packet_file_count + 1) * sizeof(kernel_file));
	
	while((bytes_read = _sceIoRead(fd, &entry, sizeof(packet_entry))) > 0)
	{
		//checks entry magic
		if(entry.magic != 0x4B504E54) //TNPK magic
			continue;
		
		//new data address aligned
		new_data = (char *)(((unsigned) new_data + 64) & 0xFFFFFFC0);
		
		//info for the kernel file entry
		new_file->name = new_name;
		new_file->buffer = new_data;
		new_file->size = entry.data_size;
		
		//reads file name and data
		_sceIoRead(fd, new_name, entry.name_size);
		_sceIoRead(fd, new_data, entry.data_size);
		
		#ifdef DEBUG
		char debug_text[96];
		_sprintf(debug_text, "%s\n\tname 0x%08X\n\tdata 0x%08X\n\tsize 0x%08X\n", new_name, new_name, new_data, entry.data_size);
		_log(debug_text);
		#endif
		
		//update pointers
		new_data += entry.data_size;
		new_name += entry.name_size;
		new_file++;
	};
	
	//closes file
	_sceIoClose(fd);
	
	#ifdef DEBUG
	_log("Packet loaded successfully\n");
	#endif
	
	return 0;
};

int hook_unknown(int arg)
{
	//saves fw version
	globals.fw_version = get_fw_version();
	
	//load modules from flash0.tn
	load_packet_files();

	fill_screen(0x00FFFFFF);
	
	#ifdef DEBUG
	_log("Calling _LoadExec000029C0()\n");
	#endif
	
	return _LoadExec000029C0(arg);
};

int hook_reboot(void * r_param, void * e_param, int api, int rnd)
{
	fill_screen(0x00FFFFF0);
	
	//decompress reboot data
	globals.reboot_size = _sceKernelGzipDecompress(0x88FC0000, 0x4000, reboot_data, 0); 
	
	unsigned address = 0xA83FF000;
	if(globals.fw_version < 0x210)
		address = 0xABDFF000;
		
	//backups 
	_memcpy(globals.unknown_big, (void *) address, sizeof(globals.unknown_big));
	
	//backup global variables
	_memcpy((void *) 0x88FB0000, &globals, sizeof(globals));
	
	#ifdef DEBUG
	_log("Calling _sceReboot()");
	#endif
	
	//reboot
	return _sceReboot(r_param, e_param, api, rnd);
};

void patch_loadexec(unsigned location, unsigned size)
{
	#ifdef DEBUG
	_log("Patching loadexec\n");
	#endif

	fill_screen(0x00FFFF00); //light blue
	_sh(0x1000, location + 0x16A6);
	_sh(0x1000, location + 0x241E);
	_sh(0x1000, location + 0x2622);

	unsigned loc, patches_done = 0;
	for(loc = location; loc < location + size; loc += 4)
	{
		if(_lw(loc) == 0x24070200) //@0x00002964 in 3.18
		{
			_memset((void *) loc, 0, 0x20);
			patches_done++;
		}
		else if(_lw(loc) == 0x02202021 && _lw(loc + 4) == 0x00401821) //@0x000029C0 in 3.18
		{
			_LoadExec000029C0 = (void *) MAKE_ADDRESS(_lw(loc - 4));
			_sw(MAKE_CALL(hook_unknown), loc - 4);
			patches_done++;
		}
		else if(_lw(loc) == 0x17C001D3) //@0x00002B9C in 3.18
		{
			_sw(0x00000000, loc); //bnez $fp, loc_000032EC
			
			_sw(0x24050002, loc + 0x188); //ori $a1, $v1, 0x2
			_sw(0x12E500B7, loc + 0x18C); //bnez $s7, loc_00003008
			_sw(0xAC570018, loc + 0x190); //sw $a1, 24($v0)
			
			_sw(MAKE_CALL(hook_reboot), loc + 0x264); //jal sub_00000000
			_sb(0x000000FC, loc + 0x2B0); //lui $at, 0x8860
			
			_sw(0x24050200, loc + 0x7FC); //li $s0, 512
			_sw(0x12650003, loc + 0x800); //beq $s3, $s0, loc_000033AC
			_sw(0x241E0210, loc + 0x804); //li $s5, 528
			_sw(0x567EFFDE, loc + 0x808); //bne $s3, $s5, loc_00003320
			_sw(MAKE_STH(loc + 8), loc + 0x810); //lui $v0, 0x0
			_sw(0x24170001, loc + 0x814); //lw $v0, 9952($v0)
			
			_sw(0x03E00008, loc + 0xB0C); //jr $ra (sceKernelGetUserLevel import) -> jr $ra
			_sw(0x24020004, loc + 0xB10); //nop -> li $v0, 4
			
			_sceReboot = (void *) location;
			patches_done++;
		};	
	};
		
	#ifdef DEBUG
	char debug_text[64];
	_sprintf(debug_text, "Patches done: %d\n", patches_done);
	_log(debug_text);
	#endif
};

void fix_kernel()
{
	_sw(0x00000000, 0x8800F768);
};

int kfunction()
{
	//set k1 to 0
	__asm("move $k1, $0;");
	
	//fills screen with blue
	fill_screen(0x00FF0000);
	
	//fixes kernel
	fix_kernel(); 
	
	//searchs for sceKernelFindModuleByName in kram
	_sceKernelFindModuleByName = NULL;
	unsigned * kp;
	for(kp = (unsigned *) 0x88000000; kp < (unsigned *) 0x883FFFA8; kp++)
	{
		if(kp[0] == 0x27BDFFE0 && kp[1] == 0xAFB40010 && kp[2] == 0xAFB3000C && kp[3] == 0xAFB20008 && kp[4] == 0x00009021 && kp[5] == 0x02409821 && kp[21] == 0x0263202A)
		{
			_sceKernelFindModuleByName = (void *) kp;
			break;
		};
	};
	
	//searches IO file functions
	_sceIoOpen = FindExport("sceIOFileManager", "IoFileMgrForKernel", 0x109F50BC);
	_sceIoRead = FindExport("sceIOFileManager", "IoFileMgrForKernel", 0x6A638D83);
	_sceIoWrite = FindExport("sceIOFileManager", "IoFileMgrForKernel", 0x42EC03AC);
	_sceIoClose = FindExport("sceIOFileManager", "IoFileMgrForKernel", 0x810C4BC3);
	_sceIoGetstat = FindExport("sceIOFileManager", "IoFileMgrForKernel", 0xACE946E8);
	
	#ifdef DEBUG
	_log_create();
	_log("Kernel function reached\n");
	#endif

	//gets load exec module info
	SceModule2 * mod = _sceKernelFindModuleByName("sceLoadExec");
	
	//patches loadexec
	patch_loadexec(mod->text_addr, mod->text_size);
	
	//flush kernel cache
	_sceKernelIcacheInvalidateAll();
	_sceKernelDcacheWritebackInvalidateAll();
	
	//gets game ID
	SceKernelGameInfo * game_info = _sceKernelGetGameInfo();
	_sprintf(globals.game_id, game_info->gameId);
	
	#ifdef DEBUG
	_log("Game ID: ");
	_log(globals.game_id);
	_log("\n");
	#endif
	
	//finds readbuffer function
	void (* _sceCtrlReadBufferPositive)(SceCtrlData *, int) = NULL;
	_sceCtrlReadBufferPositive = FindExport("sceController_Service", "sceCtrl", 0x1F803938);
	
	//reads controller input
	SceCtrlData ctrl;
	_sceCtrlReadBufferPositive(&ctrl, 1);
	
	SceIoStat status;
	
	//if R is pressed or ms0:/flash/ doesnt exist
	if(ctrl.Buttons & PSP_CTRL_RTRIGGER || _sceIoGetstat("ms0:/flash", &status) < 0)
		globals.load_mode = 4; //recovery must run!
	
	if(globals.load_mode != 4)
	{
		//loads config from file
		t_config config;
		load_config(&config);
		
		//custom menu loading
		if(config.load_eboot && _sceIoGetstat("ms0:/PSP/GAME/BOOT/FBOOT.PBP", &status) >= 0)
		{
			#ifdef DEBUG
			_log("Launching custom EBOOT\n");
			#endif
			
			//sets vshmain args
			_memset(vshmain_args, 0, sizeof(vshmain_args));
			vshmain_args[0x01] = 0x04;
			vshmain_args[0x04] = 0x20;
			vshmain_args[0x40] = 0x01;
				
			//sets parameters to execute
			struct SceKernelLoadExecVSHParam param;
			_memset(&param, 0, sizeof(param));
			param.size = sizeof(param);
			param.argp = "ms0:/PSP/GAME/BOOT/FBOOT.PBP"; 
			param.args = _strlen(param.argp) + 1;
			param.key = "game";
			param.vshmain_args_size = sizeof(vshmain_args);
			param.vshmain_args = vshmain_args;
			
			//executes menu
			int (* _LoadExecForKernel_D940C83C)(char *, struct SceKernelLoadExecVSHParam *) = (void *)(mod->text_addr + 0x1DAC);
			return _LoadExecForKernel_D940C83C("ms0:/PSP/GAME/BOOT/FBOOT.PBP", &param); 
		};
	};
	
	fill_screen(0x00000000);
	
	#ifdef DEBUG
	_log("Launching VSH\n");
	#endif
	
	//proceed
	int (* _LoadExecForKernel_08F7166C)(int) = (void *)(mod->text_addr + 0x1674);
	return _LoadExecForKernel_08F7166C(0);
};

void do_exploit()
{
	void (* _sceKernelLibcTime)(int, int, int, int, int) = NULL;
	void (* _sceKernelDcacheWritebackAll)() = NULL;
	void (* _sceUtilityLoadModule)(int) = NULL;
	
	//finds required functions
	_sceKernelLibcTime = (void *)FindImport("UtilsForUser", 0x27CC57F0); 
	_sceKernelDcacheWritebackAll = (void *)FindImport("UtilsForUser", 0x79D1C3FA);
	_sceUtilityLoadModule = (void *)FindImport("sceUtility", 0x2A2B3DE0);
	
	if(!_sceKernelLibcTime || !_sceKernelDcacheWritebackAll || !_sceUtilityLoadModule)
		error();

	//loads required modules
	_sceUtilityLoadModule(0x100);
	_sceUtilityLoadModule(0x102);
	_sceUtilityLoadModule(0x103);
	_sceUtilityLoadModule(0x104);
	_sceUtilityLoadModule(0x105);
	_sceUtilityLoadModule(0x106);
	
	//finds kxploited function
	void (* _sceLoadCertFromFlash)(unsigned, int, void **, void *, int, int *) = NULL;
	_sceLoadCertFromFlash = (void *)FindImport("sceCertLoader", 0xDD629A24); 
	
	if(!_sceLoadCertFromFlash)
		error();

	//triggers kxploit
	_sw(0x8800F764, 0x490A0D34);
	_sceLoadCertFromFlash(0, 0, (void **) 0x0400FC20, (void *) 0x0400FBC4, 2360, 0);
	
	//flush cache
	_sceKernelDcacheWritebackAll();
	
	fill_screen(0x00FF00FF);
	
	//jumps to kernel function
	_sceKernelLibcTime(0, 0, 0, 0, (unsigned)kfunction | 0x80000000); //0x00010000 + 1924
};

void _start() __attribute__((section(".text.start")));
void _start(char * path, int unload_utilities, unsigned clean_start, unsigned clean_size)
{
	void (* _sceDisplaySetFrameBuf)(unsigned *, int, int, int) = NULL;
	int (* _sceKernelDeleteFpl)(SceUID) = NULL;
	int (* _sceKernelDeleteVpl)(SceUID) = NULL;
	int (* _sceKernelFreePartitionMemory)(SceUID) = NULL;

	//gets sceDisplaySetFrameBuf()
	_sceDisplaySetFrameBuf = (void *)FindImport("sceDisplay", 0x289D82FE);
	
	//sets display buffer
	if(_sceDisplaySetFrameBuf)
		_sceDisplaySetFrameBuf((unsigned *) 0x44000000, 512, 3, 1);
		
	//fills screen with white
	fill_screen(0x00FFFFFF); 
	
	//fills memory with 0's
	_memset(&globals, 0, sizeof(globals));
	
	//gets characters until "/TN"
	int count = 0;
	char * pointer = path;
	while(pointer[0] != '/' || pointer[1] != 'T' || pointer[2] != 'N')
	{
		count++;
		pointer++;
	};
	
	//copies path
	_memcpy(globals.exploit_path, path, count); 
	
	//finds some functions
	_sceKernelDeleteFpl = (void *)FindImport("ThreadManForUser", 0xED1410E0);
	_sceKernelDeleteVpl = (void *)FindImport("ThreadManForUser", 0x89B3D48C);
	_sceKernelFreePartitionMemory = (void *)FindImport("SysMemUserForUser", 0xB6D61D02);

	unsigned i;
	for(i = clean_start; i < clean_start + clean_size; i += 4)
	{
		if(!_sceKernelDeleteFpl || _sceKernelDeleteFpl(*((unsigned *) i) < 0))
		{
			if(!_sceKernelDeleteVpl || _sceKernelDeleteVpl(*((unsigned *) i)) < 0)
			{
				if(_sceKernelFreePartitionMemory)
					_sceKernelFreePartitionMemory(*((unsigned *) i));
			};
		};
	};
	
	if(unload_utilities) //must unload utilities
	{
		void (* _sceUtilityUnloadModule)(int) = NULL;
		_sceUtilityUnloadModule = (void *)FindImport("sceUtility", 0xE49BFE92);
		if(_sceUtilityUnloadModule)
		{
			for(i = 0x100; i < 0x402; i++) //does it the other way
				_sceUtilityUnloadModule(i);
		};
	};
	
	do_exploit();
	while(1){}; //infinite loop
};