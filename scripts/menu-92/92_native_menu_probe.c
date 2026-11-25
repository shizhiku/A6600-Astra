/* Emulator-only native input callback probe. No signals; old-GLIBC pthread symbols.
 * Uses the stock callback_convert path for edge encoding and native event
 * construction rather than manually constructing UI Event objects. Mappings:
 * ENTER 0x1AC -> 0x15010050; MENU 0x1AB -> 0x15010100.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
extern int old_create(pthread_t *,const pthread_attr_t *,void *(*)(void*),void*);
extern int old_detach(pthread_t);
__asm__(".symver old_create,pthread_create@GLIBC_2.4");
__asm__(".symver old_detach,pthread_detach@GLIBC_2.4");
struct event24 {uint32_t event_code,sub_code,status,prev_status,ex_info,repeat_count;};
typedef void (*input_cb)(int,struct event24*);
static uintptr_t parse_hex(const char *p){uintptr_t v=0;while(*p){unsigned c=(unsigned char)*p++,n=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:16;if(n>15)break;v=(v<<4)|n;}return v;}
static uintptr_t find_base(void){char buf[512];uintptr_t b=0;FILE*f=fopen("/proc/self/maps","r");if(!f)return 0;while(fgets(buf,sizeof(buf),f))if(strstr(buf,"/libObj.so")&&strstr(buf,"r-xp")){b=parse_hex(buf);break;}fclose(f);return b;}
static void emit(uintptr_t b,uint32_t code,uint32_t state){struct event24 e={code,0,state,state?0:1,0,0};input_cb cb=(input_cb)(b+0x3d2fb1);fprintf(stderr,"[NATIVE92] call event=%08x status=%u base=%08lx\n",code,state,(unsigned long)b);cb(0,&e);fprintf(stderr,"[NATIVE92] returned event=%08x status=%u\n",code,state);}
static void key(uintptr_t b,uint32_t code){emit(b,code,1);usleep(100000);emit(b,code,0);}
static void *worker(void *arg){uintptr_t b=0;unsigned n;(void)arg;for(n=0;n<60;n++){sleep(1);b=find_base();if(b&&*(volatile uintptr_t*)(b+0x13f5e6c))break;}if(!b||!*(volatile uintptr_t*)(b+0x13f5e6c)){fprintf(stderr,"[NATIVE92] no InputService\n");return 0;}fprintf(stderr,"[NATIVE92] ready base=%08lx\n",(unsigned long)b);sleep(12);key(b,0x15010050);sleep(10);key(b,0x15010100);sleep(12);key(b,0x15010100);return 0;}
__attribute__((constructor)) static void init(void){char comm[32];FILE*f=fopen("/proc/self/comm","r");pthread_t t;if(!f)return;if(!fgets(comm,sizeof(comm),f)){fclose(f);return;}fclose(f);if(strncmp(comm,"im.elf",6))return;if(old_create(&t,0,worker,0)==0)old_detach(t);}
