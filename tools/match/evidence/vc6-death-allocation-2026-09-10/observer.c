#include <windows.h>
#include "replay_settings.h"
#include "probe_settings.h"

/* Only the explicitly enabled counterfactual changes a compiler value. */
typedef int (__stdcall *invoke_t)(int,char **,void *);
typedef BOOL (__stdcall *protect_t)(LPVOID,DWORD,DWORD,PDWORD);
typedef int (__fastcall *bit_test_t)(void *,unsigned long);
static HANDLE trace_file;
static unsigned char *compiler_base;
static unsigned long selector;
static unsigned long overrides;
static void write_block(void *p,unsigned long n) { DWORD written; if(!WriteFile(trace_file,p,n,&written,0)||written!=n) ExitProcess(99); }
static void __cdecl trace_before(unsigned long *regs) {
 unsigned long values[16],j;
 unsigned long *node=(unsigned long *)regs[5];
 unsigned long *operand=(unsigned long *)regs[6];
 unsigned long *temp=(unsigned long *)operand[6];
 bit_test_t bit_test=(bit_test_t)(compiler_base+0x251d);
 values[0]=(unsigned long)node; values[1]=node[1];values[2]=node[4];
 values[3]=(*(unsigned long *)(compiler_base+0x9d710)-(unsigned long)(compiler_base+0xadff4))/4;
 values[4]=temp[7];values[5]=temp[11]; values[6]=0;values[7]=(unsigned long)temp;
 for(j=1;j<=8;++j) {
  if(bit_test(*(void **)(compiler_base+0x9d6c8+j*4),temp[7])) values[6]|=1<<j;
  values[7+j]=*(unsigned long *)(compiler_base+0x9d6ec+j*4);
 }
 write_block(values,64);
#if COUNTERFACTUAL
 if(temp[7] == 449) {
  /* Pinned source: second LEA in the opening creature index calculation. */
  if(node[1] != 0x12 || (node[4] & 0xffff) != 2 || temp[11] || values[6]) ExitProcess(98);
  temp[11] = (unsigned long)(compiler_base + 0xac784); /* EAX preference. */
  ++overrides;
 }
#endif
}
static void __cdecl trace_after(unsigned long *regs) {
 unsigned long values[2];values[0]=regs[7];
 values[1]=(*(unsigned long *)(compiler_base+0x9d710)-(unsigned long)(compiler_base+0xadff4))/4;
 write_block(values,8);
}
__declspec(naked) static void hook(void) {
 __asm {
 pushfd
 pushad
 mov eax,esp
 push eax
 call trace_before
 add esp,4
 popad
 popfd
 call dword ptr [selector]
 pushfd
 pushad
 mov eax,esp
 push eax
 call trace_after
 add esp,4
 popad
 popfd
 ret
 }
}
void __stdcall start(void) {
 HMODULE module;invoke_t invoke;protect_t protect;unsigned char *site;DWORD old;int result;
 if(!LoadLibraryA(pdb_path)) ExitProcess(90);
 module=LoadLibraryA(backend_path);if(!module) ExitProcess(91);
 invoke=(invoke_t)GetProcAddress(module,"_InvokeCompilerPass@12");if(!invoke) ExitProcess(92);
 compiler_base=(unsigned char *)invoke-0x57444;
 protect=(protect_t)GetProcAddress(LoadLibraryA("kernel32.dll"),"VirtualProtect");if(!protect) ExitProcess(93);
 trace_file=CreateFileA("allocation.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);if(trace_file==INVALID_HANDLE_VALUE) ExitProcess(94);
 site=compiler_base+0x385b4;selector=(unsigned long)compiler_base+0x3c97c;
 if(site[0]!=0xe8 || (unsigned long)(site+5)+*(long *)(site+1)!=selector) ExitProcess(95);
 if(!protect(site,5,PAGE_EXECUTE_READWRITE,&old)) ExitProcess(96);
 *(long *)(site+1)=(long)hook-(long)site-5;
 result=invoke(sizeof(arguments)/sizeof(arguments[0]),arguments,0);
 CloseHandle(trace_file);
 if(!result && overrides != COUNTERFACTUAL) ExitProcess(97);
 ExitProcess(result);
}
