#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

//#include <windows.h>

#include "stecxcrypt.h"
#include "unidbg.h"

mdl_DECL;

#define __func__ __FUNCTION__

void
my_lock(void){
	printf("my_lock!\n");
}

void
my_unlock(void){
	printf("my_unlock!\n");
}

twk_inc_IMPL;

int
fprocess(FILE* fin, u8 *buf, u16 szToProcess, u16 *pSzProcessed, int isWriting){
  int lenRW = 0, len, cTry = 0;
  const int maxTry = 100;
 // try_DECL;

  do{
    len = (isWriting)
      ? fwrite(buf + lenRW, sizeof(char), szToProcess - lenRW, fin)
	  : fread (buf + lenRW, sizeof(char), szToProcess - lenRW, fin);
    if( (szToProcess - lenRW) > len ){
      asrstd( EAGAIN == errno || feof( fin ) );
	  //if(EAGAIN == errno) Sleep(100);
      asrmstd( maxTry > cTry++ );
    }
    lenRW += len;
  }while(lenRW < szToProcess && !feof(fin));

  *pSzProcessed = lenRW;
  return 0;
fail:
  return 1;
}

#define SZ_MAX_BUF16 65535

static u8 out3[SZ_MAX_BUF16];
static u8 out4[SZ_MAX_BUF16];

#define FDN 12000
int
main(void){
	EAlgo algo = XCRY_EALGO_3FISH256;
	u16 keylen = xcry_cipher_get_algo_keylen(algo);
	u16 blklen = xcry_cipher_get_algo_blklen(algo);
	FILE *fin = NULL, *fout = NULL;
	int fd[FDN];
	int eRes = 0; /* XCRY_OK */
	u8 twk[] = "abcdefghijklmno";
	u8 key[] = "abcdefghijklmnopgergegwxyz12345 abcdefghijklmnopgergegwxyz12345 abcdefghijklmnopgergegwxyz12345 abcdefghijklmnopgergegwxyz12345";
//	u8 in[] = "abcdefghijklmnopgergegwxyz12345 abcdefghijklmnopgergegwxyz12345 abcdefghijklmnopgergegwxyz12345 abcdefghijklmnopgergegwxyz12345";
	u8 out[128], out1[sizeof(out)+1];
	//u8 out_in[128];
//	u8 number[8] = {1, 2, 3, 4, 5, 6, 7, 8};
//	u64 *pOut64 = (u64*)out;
//	u64 num64 = 0x0807060504030201;
	int isEnc = 0;
	// u8 *pTwk;
	u16 sz;
	u16 szOut;
	// try_DECL;
	mdl_INI;
	out1[sizeof(out)] = '\0';
	//out[32] = '\0';
	xcry_ini(NULL, NULL);
//	xcry_ini_control(XCRY_ECTR_3FISH_SET_TWK_INC, twk_inc);

	for(isEnc = 1; isEnc>=0; isEnc--){
	//	asrstd( NULL != (fin  = fopen("in2_text.txt", "rb")) );
		asrstd( NULL != (fin  = fopen((isEnc)?"text_in.txt":"text_out.txt", "rb")) );
		asrstd( NULL != (fout = fopen((isEnc)?"text_out.txt":"text_out_in.txt", "wb")) );
		if( 0 != (eRes = xcry_open(&fd[0], algo)) ) goto fail;
		xcry_control(fd[0], XCRY_ECTR_3FISH_SET_TWK_INC, twk_inc);
		xcry_settwk(fd[0], twk, sizeof(twk));
		xcry_settwk(fd[0], key, keylen);


		printf("Opened %d!\n", fd[0]);

		if(isEnc){
			fprocess(fin, out3, sizeof(out3), &sz, 0);
			asrmstd( 0 == xcry_data_prepare(DATA, blklen, out3, sz, out3, sizeof(out3), &szOut) );
			if(0 != xcry_encrypt(fd[0], out3, szOut, out4, szOut)) goto fail;
			//memcpy(out4, out3, szOut);
			printf("szOut == %d\n", szOut);
			fprocess(fout, out4, szOut, &sz, 1);
		}else{
			u16 sz16, szAlign;
			fprocess(fin, out3, blklen, &sz, 0);
			asrmstd(sz == blklen);
			if(0 != xcry_decrypt(fd[0], out3, sz, out4, sz)) goto fail;
			//memcpy(out4, out3, sz);
			asrmstd( 0 == xcry_data_check_first_block(out4, sz) );
			sz16 = ((XCryHead *)out4)->szData;
			szAlign = ((XCryHead *)out4)->szAlignLen;
			if(szAlign < blklen - sizeof(XCryHead)){ 
				fprocess(fout, out4 + sizeof(XCryHead) + szAlign, blklen - sizeof(XCryHead) - szAlign, &sz, 1);
			}

			if(sz16 > blklen){
				fprocess(fin, out3, sz16 - blklen, &sz, 0);
				asrmstd( (sz16 - blklen) == sz );
				if(0 != xcry_decrypt(fd[0], out3, sz, out4, sz)) goto fail;
				if(szAlign < blklen - sizeof(XCryHead))
					fprocess(fout, out4, sz, &sz, 1);
				else{
					sz_t diff = (sizeof(XCryHead) + szAlign - blklen);
					fprocess(fout, out4 + diff, sz - diff, &sz, 1);
				}
			}

		}
		if (NULL != fin){ fclose(fin); fin = NULL; }
		if (NULL != fout){ fclose(fout); fout = NULL; }
	}
//	fprocess(fin, out3, sizeof(out3), &sz, 0);
//	asrmstd( XCRY_OK == xcry_data_check_first_block(out3, 32) );


	//printf("u16 == %d \n", sizeof(u16));
//	printf("%llu", num64);
	//PRINT_BITS(" == ", u64, num64, "\n");
//	printf("%llX", num64);
//	PRINT_BITS(" == ", u64, (*((u64 *)number)), "\n\n");

//	printf("%llu", num64);
//	PRINT_BITS(" == ", u64, num64, "\n\n");

//	printf("Starting... %d \n", sizeof(in));
	//xcry_ini(my_lock, my_unlock);
//	xcry_ini(NULL, NULL);
//	xcry_ini_control(XCRY_ECTR_3FISH_SET_TWK_INC, twk_inc);
	//if( XCRY_OK != (eRes = xcry_open(&fd[0], XCRY_EALGO_3FISH256)) ) goto fail;
	//printf("Opened %d!\n", fd[0]);
//	printf("input : %s\n", in);
	//xcry_settwk(fd[0], twk, sizeof(twk));
	//xcry_settwk(fd[0], key, sizeof(key));
//	if(XCRY_OK != xcry_encrypt(fd[0], in, sizeof(in), out, sizeof(out))) goto fail;
	//xcry_gettwk(fd[0], &pTwk);
	//printf("xcry_gettwk: %d\n", memcmp(pTwk, twk, 2*sizeof(u64)));
	//xcry_settwk(fd[0], twk, sizeof(twk));
	//xcry_gettwk(fd[0], &pTwk);
	//printf("xcry_gettwk: %d\n", memcmp(pTwk, twk, 2*sizeof(u64)));
	//if(XCRY_OK != xcry_decrypt(fd[0], out, sizeof(out), out_in, sizeof(out_in))) goto fail;
	//printf("result: %s\n", out_in);
//	if( XCRY_OK != (eRes = xcry_close(fd[0])) ) goto fail;
//	printf("Closed! %d\n", fd[0]);

/*	for(j = 0; j < 2; j++){
		for(i = 0; i < FDN/2; i++){
			if( XCRY_OK != (eRes = xcry_open(&fd[i], XCRY_EALGO_3FISH256)) ) goto fail;
			printf("Opened %d!\n", fd[i]);
		}
		for(i = 0; i < FDN/2; i++){
			if( XCRY_OK != (eRes = xcry_close(fd[i])) ) goto fail;
			printf("Closed! %d\n", fd[i]);
		}
		for(i = 0; i < FDN*3/4; i++){
			if( XCRY_OK != (eRes = xcry_open(&fd[i], XCRY_EALGO_3FISH256)) ) goto fail;
			printf("Opened %d!\n", fd[i]);
		}
		for(i = 0; i < FDN*3/4; i++){
			if( XCRY_OK != (eRes = xcry_close(fd[i])) ) goto fail;
			printf("Closed! %d\n", fd[i]);
		}

		for(i = 0; i < FDN; i++){
			if( XCRY_OK != (eRes = xcry_open(&fd[i], XCRY_EALGO_3FISH256)) ) goto fail;
			printf("Opened %d!\n", fd[i]);
		}
		for(i = 0; i < FDN; i++){
			if( XCRY_OK != (eRes = xcry_close(fd[i])) ) goto fail;
			printf("Closed! %d\n", fd[i]);
		}

	} */
fail:
	
	xcry_release();
	printf("Released!\n");
	if (NULL != fin) fclose(fin);
	if (NULL != fout) fclose(fout);
	getchar();
	return 0;
}
