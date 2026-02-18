/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: console_printf */
/* function_mapped: console_printf */
/* address: 0x00401870 */
/* byte_range: [14998, 15350) */
/* console_printf @ 00401870 */

/* formats then pushes line */

char console_printf(void *console_state, char *fmt, ...)

{
  char cVar1;
  
  cVar1 = '\0';
  if (*(char *)((int)console_state + 0xc) != '\0') {
    crt_vsprintf(&DAT_0047f2cc,fmt,&stack0x0000000c);
    cVar1 = console_push_line(console_state,&DAT_0047f2cc);
  }
  return cVar1;
}
