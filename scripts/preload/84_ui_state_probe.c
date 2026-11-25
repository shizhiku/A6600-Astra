/* Emulator-only, late Appframework state sampler. No UI mutation. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
extern int old_pthread_create(pthread_t *,const pthread_attr_t *,void *(*)(void*),void*);
extern int old_pthread_detach(pthread_t);
__asm__(".symver old_pthread_create,pthread_create@GLIBC_2.4");
__asm__(".symver old_pthread_detach,pthread_detach@GLIBC_2.4");
static uintptr_t hex(const char *p){uintptr_t v=0;for(;;p++){unsigned c=*p;unsigned n=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:16;if(n>15)break;v=(v<<4)|n;}return v;}
static uintptr_t base(void){char line[512];FILE *f=fopen("/proc/self/maps","r");uintptr_t b=0;if(!f)return 0;while(fgets(line,sizeof(line),f)){if(strstr(line,"/libObj.so")&&strstr(line,"r-xp")){b=hex(line);break;}}fclose(f);return b;}
static void *sample(void *unused){unsigned i;uintptr_t b;(void)unused;for(i=0;i<40;i++){sleep(1);b=base();if(!b)continue;fprintf(stderr,"[UI84] pid=%d base=%08lx mode=%u inputsvc=%08x fonthead=%08x\n",getpid(),(unsigned long)b,*(volatile uint32_t*)(b+0x142c0a0),*(volatile uint32_t*)(b+0x13f5e6c),*(volatile uint32_t*)(b+0x13f64fc));{uintptr_t vm=*(volatile uint32_t*)(b+0x142be7c);if(vm){uintptr_t be=*(volatile uint32_t*)(vm+0x14);fprintf(stderr,"[UI84] vm=%08lx backend=%08lx",(unsigned long)vm,(unsigned long)be);if(be)fprintf(stderr," dirty=%u obj8=%08x obj10=%08x sync=%08x",*(volatile unsigned char*)(be+0x29),*(volatile uint32_t*)(be+8),*(volatile uint32_t*)(be+0x10),*(volatile uint32_t*)(be+0x2c));fprintf(stderr,"\n");}}}return 0;}
__attribute__((constructor)) static void init(void){char comm[32]={0};FILE*f=fopen("/proc/self/comm","r");pthread_t t;if(!f)return;if(!fgets(comm,sizeof(comm),f)){fclose(f);return;}fclose(f);if(strncmp(comm,"im.elf",6))return;if(old_pthread_create(&t,0,sample,0)==0)old_pthread_detach(t);}
