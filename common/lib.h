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

#define MAKE_STH(f)  ((((unsigned)(f) & 0x0FFFFFFC) >> 2) | 0x08000000)
#define MAKE_ADDRESS(f) ((((unsigned)(f) & 0xF3FFFFFF) << 2) | 0x80000000) 
#define MAKE_JUMP(f) ((((unsigned)(f) >> 2) & 0x03FFFFFFF) | 0x08000000)
#define MAKE_CALL(f) ((((unsigned)(f) >> 2) & 0x03FFFFFFF) | 0x0C000000) 

void _memset(void * destination, unsigned char value, int size);
void _memcpy(void * destination, void * source, int size);
int _strcmp(const char *s1, const char *s2);
int _strlen(const char * str);
char * _strchr(char * str, char c);
int ValidUserAddress(void * addr);
unsigned FindImport(char * libname, unsigned nid);
void * FindExport(const char * modulename, const char * library, u32 nid);

#endif