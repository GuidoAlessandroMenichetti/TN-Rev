#ifndef LIB_H
#define LIB_H

#include <pspdisplay.h>
#include <pspctrl.h>
#include <pspkernel.h>
#include <pspge.h>
#include <pspdebug.h>
#include <pspaudio.h>
#include <psputility.h>
#include <pspumd.h>
#include <psptypes.h>
#include <pspimpose_driver.h>
#include <psputility.h>
#include <psploadexec_kernel.h>

void memset(unsigned char * destination, unsigned char value, unsigned size);
void memcpy(unsigned char * destination, const unsigned char * source, int size);
int ValidUserAddress(void * addr);
unsigned FindImport(char * libname, unsigned nid);
unsigned FindFunction(const char * modulename, const char * library, unsigned nid);

#endif