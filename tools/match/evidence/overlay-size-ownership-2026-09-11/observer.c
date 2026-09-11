#include <windows.h>
#include "replay_settings.h"
typedef int (__stdcall *invoke_t)(int,char **,void *);
typedef BOOL (__stdcall *protect_t)(LPVOID,DWORD,DWORD,PDWORD);
/* Observes the loaded compiler. Neither hook changes compiler data. */
static HANDLE trace_file;static unsigned char *compiler_base;
static unsigned long saved_count, saved_symbols[16384];
static void write_block(void *p,unsigned long n) { DWORD written; if(!WriteFile(trace_file,p,n,&written,0)||written!=n) ExitProcess(99); }
static void __cdecl trace_phase(unsigned long phase,unsigned long *regs) {
 unsigned long n=*(unsigned long *)(compiler_base+0x9f20c),i,j,count;
 unsigned long head=*(unsigned long *)(compiler_base+0x9f220);
 unsigned long *symbols=*(unsigned long **)(compiler_base+0x9f218);
 unsigned long **edges=*(unsigned long ***)(compiler_base+0x9f204);
 unsigned long zero[21]={0};
 if(phase==1) {
  if(!saved_count) return;
  write_block(&phase,4);write_block(&saved_count,4);
  for(i=0;i<saved_count;++i) {
   unsigned long s=saved_symbols[i],d=*(unsigned long *)s;
   write_block(&s,4);write_block((void *)s,84);
   write_block(d?(void *)d:zero,64);
  }
  saved_count=0;return;
 }
 if(n>16384 || saved_count) ExitProcess(97);
 saved_count=n;write_block(&phase,4);
 write_block(&n,4);write_block(&head,4);
 for(i=0;i<n;++i) {
  unsigned long s=symbols[i],d=s?*(unsigned long *)s:0;
  unsigned long *bits=edges[i]?(unsigned long *)edges[i][0]:0;
  saved_symbols[i]=s;
  count=0;for(j=(unsigned long)bits;j;j=*(unsigned long *)(j+4)) { if(++count>1024) ExitProcess(98); }
  write_block(&s,4);write_block(s?(void *)s:zero,84);write_block(d?(void *)d:zero,64);
  write_block(&count,4);
  for(j=(unsigned long)bits;j;j=*(unsigned long *)(j+4))write_block((void *)j,12);
 }
}

static unsigned long target_0;
__declspec(naked) static void hook_0(void) {
 __asm {
 pushfd
 pushad
 mov eax,esp
 push eax
 push 0
 call trace_phase
 add esp,8
 popad
 popfd
 jmp dword ptr [target_0]
 }
}
static unsigned long target_1;
__declspec(naked) static void hook_1(void) {
 __asm {
 pushfd
 pushad
 mov eax,esp
 push eax
 push 1
 call trace_phase
 add esp,8
 popad
 popfd
 jmp dword ptr [target_1]
 }
}
void __stdcall start(void) {
 HMODULE module; invoke_t invoke; protect_t protect; unsigned char *base,*site; DWORD old; int result;
 if(!LoadLibraryA(pdb_path)) ExitProcess(90);
 module=LoadLibraryA(backend_path);if(!module) ExitProcess(91);
 invoke=(invoke_t)GetProcAddress(module,"_InvokeCompilerPass@12");if(!invoke) ExitProcess(92);
 base=(unsigned char *)invoke-0x57444;compiler_base=base;
 protect=(protect_t)GetProcAddress(LoadLibraryA("kernel32.dll"),"VirtualProtect");if(!protect) ExitProcess(93);
 trace_file=CreateFileA("phases.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);if(trace_file==INVALID_HANDLE_VALUE) ExitProcess(94);
site=base+0x33cde; target_0=(unsigned long)base+0x4b617;
 if(site[0]!=0xe8||(unsigned long)(site+5)+*(long *)(site+1)!=target_0) ExitProcess(95);
 if(!protect(site,5,PAGE_EXECUTE_READWRITE,&old)) ExitProcess(96);
 *(long *)(site+1)=(long)hook_0-(long)site-5;
site=base+0x5840f; target_1=(unsigned long)base+0x34032;
 if(site[0]!=0xe8||(unsigned long)(site+5)+*(long *)(site+1)!=target_1) ExitProcess(95);
 if(!protect(site,5,PAGE_EXECUTE_READWRITE,&old)) ExitProcess(96);
 *(long *)(site+1)=(long)hook_1-(long)site-5;
result=invoke(sizeof(arguments)/sizeof(arguments[0]),arguments,0);CloseHandle(trace_file);ExitProcess(result);}
