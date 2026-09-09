extern "C" char *duplicate(char *);
extern "C" int scan(char *, const char *, ...);
extern "C" int __stdcall close_handle(void *);
extern "C" void * __stdcall open_handle();
extern "C" int __stdcall query(unsigned long *,char *,unsigned long *);
extern "C" void observe(int,int,int);
char *url;
extern "C" void array_outputs(char *link,char *newest) {
 int v[3];
 url=duplicate(link);
 scan(newest,"%d.%d.%d",&v[0],&v[1],&v[2]);
 observe(v[0],v[1],v[2]);
}
extern "C" void scalar_outputs(char *link,char *newest) {
 int major,minor,patch;
 url=duplicate(link);
 scan(newest,"%d.%d.%d",&major,&minor,&patch);
 observe(major,minor,patch);
}
extern "C" void close_local() {
 void *request=open_handle();
 if(request) close_handle(request);
}
extern "C" void query_outputs(char *data) {
 unsigned long length=0x8000;
 unsigned long error;
 query(&error,data,&length);
}
