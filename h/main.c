#include "../common/lib.h"
#include "exploit_config.h"
#define TN_PATH SAVEDATA_PATH"TN.BIN" //do not touch me


#define TN_LOAD_ADDRESS 0x00010000 //where tn.bin is linked, check /loader/linker.x

void _start() __attribute__((section(".text.start")));
void _start()
{
	//search for needed imports
	int (* _sceIoOpen)(const char *, int, int) = (void *)FindImport("IoFileMgrForUser", 0x109F50BC);
	int (* _sceIoRead)(int, void *, unsigned) = (void *)FindImport("IoFileMgrForUser", 0x6A638D83);
	void (* _sceIoClose)(int) = (void *)FindImport("IoFileMgrForUser", 0x810C4BC3);
	
	//open file
	int fd = _sceIoOpen(TN_PATH, 1, 0);

	//read tn.bin bytes
	char buffer[0x10000];
	int bytes_read = _sceIoRead(fd, buffer, sizeof(buffer));
	
	//close file
	_sceIoClose(fd);
	
	//copy to launch address
	memcpy(TN_LOAD_ADDRESS, buffer, bytes_read);
	
	//jump to tn-v loader
	void (* start_tnv)(char *, int, unsigned, unsigned) = (void *) TN_LOAD_ADDRESS;
	start_tnv(TN_PATH, UNLOAD_MODULES, CLEAN_START, CLEAN_SIZE);	
};