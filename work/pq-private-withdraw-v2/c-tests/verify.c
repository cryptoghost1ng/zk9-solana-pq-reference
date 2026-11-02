/* Real cross-language ABI calls. Synthetic fixtures only; no node or bank. */
#include "../include/verifier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int checks=0;
static void check(int condition,const char *name) {
  if(!condition){fprintf(stderr,"FAIL %s\n",name);exit(1);}checks++;
}
static uint8_t *read_wire(const char *path,size_t *size) {
  FILE *f=fopen(path,"rb");check(f!=NULL,"file open");
  check(fseek(f,0,SEEK_END)==0,"seek");long len=ftell(f);
  check(len>0 && len<5000000,"file size");check(fseek(f,0,SEEK_SET)==0,"rewind");
  uint8_t *b=malloc((size_t)len);check(b!=NULL,"allocation");
  check(fread(b,1,(size_t)len,f)==(size_t)len,"read");check(fclose(f)==0,"close");*size=(size_t)len;return b;
}
int main(int argc,char **argv) {
  check(argc==3,"v2 wire and v1 reference required");
  size_t size,oldsize;uint8_t *b=read_wire(argv[1],&size),*old=read_wire(argv[2],&oldsize);
  uint8_t ctx[96];memset(ctx,1,32);memset(ctx+32,2,32);memset(ctx+64,3,32);
  check(zk9_pq_withdraw32_verify(NULL,96,1,b,size)==1,"null context");
  check(zk9_pq_withdraw32_verify(ctx,96,1,NULL,size)==1,"null proof");
  check(zk9_pq_withdraw32_verify(ctx,95,1,b,size)==1,"context size");
  check(zk9_pq_withdraw32_verify(ctx,96,0,b,size)==1,"zero fee");
  check(zk9_pq_withdraw32_verify(ctx,96,1,b,3945)==1,"empty proof");
  uint8_t *oversized=calloc(5000000,1);check(oversized!=NULL,"oversize allocation");
  check(zk9_pq_withdraw32_verify(ctx,96,1,oversized,5000000)==1,"oversize bound");free(oversized);
  check(zk9_pq_withdraw32_verify(ctx,96,1,b,size)==-1,"uninitialized");
  check(zk9_pq_withdraw32_init()==0,"initialize");check(zk9_pq_withdraw32_init()==0,"idempotent initialize");
  check(zk9_pq_withdraw32_verify(ctx,96,1,b,size)==0,"valid withdrawal");
  check(zk9_pq_withdraw32_verify(ctx,96,1,b,size)==0,"repeated verification");
  check(zk9_pq_withdraw32_verify(ctx,96,2,b,size)==1,"wrong expected fee");
  ctx[0]^=1;check(zk9_pq_withdraw32_verify(ctx,96,1,b,size)==1,"wrong network");ctx[0]^=1;
  ctx[32]^=1;check(zk9_pq_withdraw32_verify(ctx,96,1,b,size)==1,"wrong genesis");ctx[32]^=1;
  ctx[64]^=1;check(zk9_pq_withdraw32_verify(ctx,96,1,b,size)==1,"wrong asset");ctx[64]^=1;
  check(zk9_pq_withdraw32_verify(ctx,96,1,old,oldsize)==1,"v1 rejection");
  const size_t positions[]={8,116,117,125,145,156,157,221,285,349,413,481,2213,size-1};
  for(size_t i=0;i<sizeof(positions)/sizeof(*positions);i++) {
    b[positions[i]]^=1;check(zk9_pq_withdraw32_verify(ctx,96,1,b,size)==1,"mutated envelope");b[positions[i]]^=1;
  }
  check(zk9_pq_withdraw32_verify(ctx,96,1,b,size-1)==1,"truncation");
  check(zk9_pq_withdraw32_verify(ctx,96,1,b,size)==0,"valid after invalid inputs");
  free(b);free(old);printf("{\"status\":\"PASS\",\"checks\":%d,\"scope\":\"C-linked native ABI only\"}\n",checks);return 0;
}
