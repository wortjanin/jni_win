#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "unitls.h"
//#include "unidbg.h"
#define ASRD(WHAT, DO) if(!(WHAT)) { DO; }

#include "stecxcrypt.h"
#include "stecxcrypt_internal.h"

#define SZ_INC_ARRAY 16

//mdl_DECL;

xcry_error_IMPL;

#define fp_DECL(VAR_NAME, FP_NAME, ... ) \
	typedef int (*FP_NAME)(__VA_ARGS__); \
	int FP_NAME ## S(__VA_ARGS__); /* Thread safe */ \
	int FP_NAME ## U(__VA_ARGS__); /* Thread unsafe */ \
	static FP_NAME VAR_NAME

fp_DECL(g_fpOpen, xcry_openT, int* fd, EAlgo algo);
fp_DECL(g_fpClose, xcry_closeT, int fd);
fp_DECL(g_fpControl, xcry_controlT, int fd, ECtr eCtl, void *pData);
fp_DECL(g_fpSetTwk, xcry_settwkT, int fd, u8 *pTweak, sz_t szTweakLen);
fp_DECL(g_fpGetTwk, xcry_gettwkT, int fd, u8 **ppTweak);
fp_DECL(g_fpSetKey, xcry_setkeyT, int fd, u8 *pKey, sz_t szKeyLen);
fp_DECL(g_fpEncrypt, xcry_encryptT, int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen);
fp_DECL(g_fpDecrypt, xcry_decryptT, int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen);

static xcry_mutex_callback g_fpLock = NULL;
static xcry_mutex_callback g_fpUnLock = NULL;

/* INTERFACE */
void
xcry_ini(xcry_mutex_callback mutex_cb_lock,  xcry_mutex_callback mutex_cb_unlock){
	int stime;
	long ltime;
	ltime = time(NULL);
	stime = (unsigned) ltime/2;
	srand(stime);

	g_fpLock = mutex_cb_lock;
	g_fpUnLock = mutex_cb_unlock;
	if(NULL == g_fpLock && NULL == g_fpUnLock){
		g_fpOpen	= xcry_openTU;
		g_fpClose	= xcry_closeTU;
		g_fpControl = xcry_controlTU;
		g_fpSetTwk	= xcry_settwkTU;
		g_fpGetTwk	= xcry_gettwkTU;
		g_fpSetKey  = xcry_setkeyTU;
		g_fpEncrypt = xcry_encryptTU;
		g_fpDecrypt = xcry_decryptTU;
	}
	else{
		g_fpOpen	= xcry_openTS;
		g_fpClose	= xcry_closeTS;
		g_fpControl = xcry_controlTS;
		g_fpSetTwk	= xcry_settwkTS;
		g_fpGetTwk	= xcry_gettwkTS;
		g_fpSetKey  = xcry_setkeyTS;
		g_fpEncrypt = xcry_encryptTS;
		g_fpDecrypt = xcry_decryptTS;
	}
}

/* INTERFACE */
sz_t
xcry_cipher_get_algo_keylen(EAlgo algo){
	switch(algo){
		case XCRY_EALGO_3FISH256: return 32;
		case XCRY_EALGO_3FISH512: return 64;
		case XCRY_EALGO_3FISH1024: return 128;
		default: break;
	}
	return 0;
}

/* INTERFACE */
sz_t
xcry_cipher_get_algo_blklen(EAlgo algo){
	switch(algo){
		case XCRY_EALGO_3FISH256: return 32;
		case XCRY_EALGO_3FISH512: return 64;
		case XCRY_EALGO_3FISH1024: return 128;
		default: break;
	}
	return 0;
}

/* INTERFACE */
int
xcry_open(int* hd, EAlgo algo){
	return g_fpOpen(hd, algo);
}

#define TS_FUNBODY_IMPL(XCRY_RTYPE, XCRY_FNAME_TU, ...)  \
	XCRY_RTYPE res; \
	g_fpLock(); \
	res =  XCRY_FNAME_TU ( __VA_ARGS__ ); \
	g_fpUnLock(); \
	return res

int
xcry_openTS(int* fd, EAlgo algo){
	TS_FUNBODY_IMPL(int, xcry_openTU, fd, algo);
}

struct XCryArray{
	sz_t		szXCryAlgo;
	XCryAlgo	**aaXCryAlgo;	

	ringBuf_DECL(sz_t, aaXCryAlgo);
};
#define zeroXCryArray_INI     \
	/*.szXCryAlgo  = */ 0,    \
	/*.aaXCryAlgo  = */ NULL, \
	                          \
	ringBuf_INI(aaXCryAlgo)

static struct XCryArray g_a = { zeroXCryArray_INI };
static struct XCryArray  * const g_p = &g_a;

static const XCryAlgo g_zeroXCryAlgo = { zeroXCryAlgo_INI };

int
xcry_openTU(int* fd, EAlgo algo){
	ERes eRes = XCRY_OK;
	XCryAlgo* pAlgo;
	sz_t szPrev = g_p->szXCryAlgo, iP;
	int freeArraysOnError = 0;
	int iFd = -1;

	if(NULL == g_p->aaXCryAlgo){
		freeArraysOnError = 1;
		g_p->szXCryAlgo = SZ_INC_ARRAY;
		if( NULL == ( mallocX(g_p->aaXCryAlgo, g_p->szXCryAlgo) ) || 
			NULL == ( ringBuf_aNumFree_IMPL(g_p, aaXCryAlgo) = calloc(g_p->szXCryAlgo, ringBuf_szof_IMPL(g_p, aaXCryAlgo)) ) )
			{ eRes = XCRY_NOMEM;  goto fail; }
		pAlgo = NULL;
		memptrset(g_p->aaXCryAlgo, &pAlgo, sizeof(pAlgo), g_p->szXCryAlgo);
		for(iP = 0; iP < g_p->szXCryAlgo; iP++){
			if( NULL == ( *(g_p->aaXCryAlgo + iP) = malloc(sizeof(XCryAlgo)) ) )
				{ eRes = XCRY_NOMEM;  goto fail; }
			memcpy(*(g_p->aaXCryAlgo + iP), &g_zeroXCryAlgo, sizeof(g_zeroXCryAlgo));
		}
	}
		
	if(ringBuf_isFull_IMPLX(g_p, aaXCryAlgo, g_p->szXCryAlgo)){
		XCryAlgo **aaXCryAlgoNew = NULL;
		sz_t *aNumFreeNew = NULL;
		g_p->szXCryAlgo += SZ_INC_ARRAY;
		if( NULL == ( mallocX(aaXCryAlgoNew, g_p->szXCryAlgo) ) || 
			NULL == ( aNumFreeNew = calloc(g_p->szXCryAlgo, ringBuf_szof_IMPL(g_p, aaXCryAlgo)) ) )
			{ eRes = XCRY_NOMEM; freeX(aaXCryAlgoNew); goto fail; }

		memcpy(aaXCryAlgoNew, g_p->aaXCryAlgo, szPrev * sizeof(pAlgo)); 
		pAlgo = NULL;
		memptrset(aaXCryAlgoNew + szPrev, &pAlgo, sizeof(pAlgo), SZ_INC_ARRAY);
		for(iP = szPrev; iP < g_p->szXCryAlgo; iP++){
			if(NULL == ( *(aaXCryAlgoNew + iP) = malloc(sizeof(XCryAlgo)) ) ){
				for(iP = szPrev; iP < g_p->szXCryAlgo; iP++){
					freeX( *(aaXCryAlgoNew + iP) );
				}
				eRes = XCRY_NOMEM; freeX(aaXCryAlgoNew); goto fail;
			}
			memcpy(*(aaXCryAlgoNew + iP), &g_zeroXCryAlgo, sizeof(g_zeroXCryAlgo));
		}
		free(g_p->aaXCryAlgo);
		g_p->aaXCryAlgo = aaXCryAlgoNew;
		memcpy(aNumFreeNew, ringBuf_aNumFree_IMPL(g_p, aaXCryAlgo), szPrev * ringBuf_szof_IMPL(g_p, aaXCryAlgo));
		free(ringBuf_aNumFree_IMPL(g_p, aaXCryAlgo));
		ringBuf_aNumFree_IMPL(g_p, aaXCryAlgo) = aNumFreeNew;
	}

	ringBuf_popFreeNum_IMPLX(iFd, g_p, aaXCryAlgo, g_p->szXCryAlgo, goto fail);
	pAlgo = *(g_p->aaXCryAlgo + iFd);
	switch(algo){
		case XCRY_EALGO_3FISH256:
		case XCRY_EALGO_3FISH512:
		case XCRY_EALGO_3FISH1024:
			if(XCRY_OK != (eRes = xcry_3fish_open(pAlgo, algo))) goto fail;
			break;
		default: eRes = XCRY_INVALID_ALGORITHM; goto fail;
	}
	*fd = iFd;
	return eRes;
fail:
	if(XCRY_OK == eRes) eRes = XCRY_ERROR;
	// ... release resources
	if(-1 != iFd){
		ringBuf_pushFreeNum_IMPLX2(g_p, iFd, aaXCryAlgo, g_p->szXCryAlgo);
	}

	if(freeArraysOnError){
		if( NULL != g_p->aaXCryAlgo )
			for(iP = 0; iP < g_p->szXCryAlgo; iP++){
				freeX( *(g_p->aaXCryAlgo + iP) );
			}
		freeX(ringBuf_aNumFree_IMPL(g_p, aaXCryAlgo));
		freeX(g_p->aaXCryAlgo);
	}

	g_p->szXCryAlgo = szPrev;
	*fd = -1;
	return eRes;
}

/* INTERFACE */
int
xcry_close(int fd){
	return g_fpClose(fd);
}

int
xcry_closeTS(int fd){
	TS_FUNBODY_IMPL(int, xcry_closeTU, fd);
}

int
xcry_closeTU(int fd){
	XCryAlgo *pAlgo;
	ERes eRes = XCRY_OK;
	if(0 > fd || fd >= g_p->szXCryAlgo)	return XCRY_INVALID_INPUT;
	pAlgo = *(g_p->aaXCryAlgo + fd);
	if(NULL == pAlgo->iAlgo)	return XCRY_INVALID_INPUT;

	if( XCRY_OK != ( eRes = pAlgo->iAlgo->fp_close(pAlgo) ) ) goto end;

	ringBuf_pushFreeNum_IMPLX2(g_p, fd, aaXCryAlgo, g_p->szXCryAlgo);

end:
	return eRes;
}

/* INTERFACE */
void
xcry_release(void){
	sz_t iFd;
	for(iFd = 0; iFd < g_p->szXCryAlgo; iFd++){
		xcry_closeTU(iFd);
		freeX(*(g_p->aaXCryAlgo + iFd));
	}
	freeX(ringBuf_aNumFree_IMPL(g_p, aaXCryAlgo));
	freeX(g_p->aaXCryAlgo);
	g_p->szXCryAlgo = 0;
}
/* INTERFACE */
int
xcry_control(int hd, ECtr eCtl, void *pData){
	return g_fpControl(hd, eCtl, pData);
}
//ERes
//xcry_ini_control(ECtr eCtl, void *pData){
//	switch(eCtl){
//		case XCRY_ECTR_3FISH_SET_TWK_INC: return xcry_3fish_ini_control(eCtl, pData); 
//		default: break;
//	}
//	return XCRY_INVALID_INPUT;
//}

/* INTERFACE */
int
xcry_settwk(int fd, u8 *pTweak, sz_t szTweakLen){
	return g_fpSetTwk(fd, pTweak, szTweakLen);
}

/* INTERFACE */
int 
xcry_gettwk(int fd, u8 **ppTweak){
	return g_fpGetTwk(fd, ppTweak);
}


/* INTERFACE */
int 
xcry_setkey(int fd, u8 *pKey, sz_t szKeyLen){
	return g_fpSetKey(fd, pKey, szKeyLen);
}

/* INTERFACE */
int 
xcry_encrypt(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){
	return g_fpEncrypt(fd, pInBuf, szInBufLen, pOutBuf, szOutBufLen);
}

/* INTERFACE */
int 
xcry_decrypt(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){
	return g_fpDecrypt(fd, pInBuf, szInBufLen, pOutBuf, szOutBufLen);
}


#define READ_pAlgo_TS \
	XCryAlgo *pAlgo; \
	if(0 > fd || fd >= g_p->szXCryAlgo) return XCRY_INVALID_INPUT; \
	g_fpLock(); \
	pAlgo = *(g_p->aaXCryAlgo + fd); \
	g_fpUnLock() 

#define READ_pAlgo_TU \
	XCryAlgo *pAlgo; \
	if(0 > fd || fd >= g_p->szXCryAlgo) return XCRY_INVALID_INPUT; \
	pAlgo = *(g_p->aaXCryAlgo + fd) 


int
xcry_controlTS(int fd, ECtr eCtl, void *pData){
	READ_pAlgo_TS;
	return pAlgo->iAlgo->fp_control(pAlgo, eCtl, pData);
}

int
xcry_controlTU(int fd, ECtr eCtl, void *pData){
	READ_pAlgo_TU;
	return pAlgo->iAlgo->fp_control(pAlgo, eCtl, pData);
}

int 
xcry_settwkTS(int fd, u8 *pTweak, sz_t szTweakLen){ /* Thread safe */
	READ_pAlgo_TS;
	return pAlgo->iAlgo->fp_settwk(pAlgo, pTweak, szTweakLen);
}
int 
xcry_settwkTU(int fd, u8 *pTweak, sz_t szTweakLen){ /* Thread unsafe */
	READ_pAlgo_TU;
	return pAlgo->iAlgo->fp_settwk(pAlgo, pTweak, szTweakLen);
}

int 
xcry_gettwkTS(int fd, u8 **ppTweak){ /* Thread safe */
	READ_pAlgo_TS;
	return pAlgo->iAlgo->fp_gettwk(pAlgo, ppTweak);
}
int 
xcry_gettwkTU(int fd, u8 **ppTweak){ /* Thread unsafe */
	READ_pAlgo_TU;
	return pAlgo->iAlgo->fp_gettwk(pAlgo, ppTweak);
}

int 
xcry_setkeyTS(int fd, u8 *pKey, sz_t szKeyLen){
	READ_pAlgo_TS;
	return pAlgo->iAlgo->fp_setkey(pAlgo, pKey, szKeyLen);
}
int 
xcry_setkeyTU(int fd, u8 *pKey, sz_t szKeyLen){
	READ_pAlgo_TU;
	return pAlgo->iAlgo->fp_setkey(pAlgo, pKey, szKeyLen);
}

int
xcry_encryptTS(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){
	READ_pAlgo_TS;
	return pAlgo->iAlgo->fp_encrypt(pAlgo, pInBuf, szInBufLen, pOutBuf, szOutBufLen);
}
int 
xcry_encryptTU(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){
	READ_pAlgo_TU;
	return pAlgo->iAlgo->fp_encrypt(pAlgo, pInBuf, szInBufLen, pOutBuf, szOutBufLen);
}

int 
xcry_decryptTS(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){
	READ_pAlgo_TS;
	return pAlgo->iAlgo->fp_decrypt(pAlgo, pInBuf, szInBufLen, pOutBuf, szOutBufLen);
}
int 
xcry_decryptTU(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){
	READ_pAlgo_TU;
	return pAlgo->iAlgo->fp_decrypt(pAlgo, pInBuf, szInBufLen, pOutBuf, szOutBufLen);
}




void fillAlign(u8 *pBuf, sz_t szAlignLen){
	int num;
	sz_t i = 0, iMax = szAlignLen/sizeof(num), sz = szAlignLen % sizeof(num);
	for(i = 0; i < iMax; i += sizeof(num)){
		num = rand();
		memcpy(pBuf + i, &num, sizeof(num));
	}
	if(sz > 0){
		num = rand();
		memcpy(pBuf + i, &num, sz);
	}
}

/* INTERFACE */
int
xcry_data_prepare(EDataType eDataType, u16 szBlock, const u8 *pInBuf, u16 szInBuf, u8 *pOutBuf, u16 szOutBuf, u16 *pSzOutBuf){
	XCryHead xcryHead = { zeroXCryHead_INI };
	sz_t szDataTot = szInBuf + szBlock, i;
	u16 chkSum;
	if(0 == szBlock || szBlock > 255 || szOutBuf < szDataTot || szDataTot > 65535) return XCRY_INVALID_LEN;
	if(NULL == pInBuf || NULL == pOutBuf) return XCRY_INVALID_INPUT;

	xcryHead.dataType = eDataType;
	xcryHead.szData = szInBuf + sizeof(xcryHead); /* sz == 2B, dataType == 1B, szAlignLen == 1B, chkSumOfFirstBlock == 2B, random num == 2B*/
	xcryHead.szAlignLen = xcryHead.szData % szBlock;
	if(0 != xcryHead.szAlignLen){ 
		xcryHead.szAlignLen = szBlock - xcryHead.szAlignLen; 
		xcryHead.szData += xcryHead.szAlignLen; }
	*pSzOutBuf = xcryHead.szData;
	xcryHead.randNum = (u16)rand();

	if(0 != szInBuf) memmove(pOutBuf + ( sizeof(xcryHead) + xcryHead.szAlignLen ), pInBuf, szInBuf);
	fillAlign(pOutBuf + sizeof(xcryHead), xcryHead.szAlignLen);
	memcpy(pOutBuf, &xcryHead, sizeof(xcryHead));

	chkSum = 0;
	for(i = 0; i < szBlock; i+= sizeof(u16)){
		chkSum += *((u16 *)(pOutBuf + i)) * ((0 == (i % 2)) ? 1 : 3);
	}
	((XCryHead *)(pOutBuf))->chkSum = chkSum;
	return XCRY_OK;
}

/* INTERFACE */
int
xcry_data_check_first_block(const u8 *pInBuf, sz_t szBlock){
	sz_t i;
	u16 chkSum, oldChkSum;
	if(0 == szBlock || NULL == pInBuf) return XCRY_INVALID_INPUT;

	oldChkSum = ((XCryHead *)pInBuf)->chkSum;

	chkSum = 0;
	for(i = 0; i < szBlock; i+= sizeof(u16)){
		chkSum += *((u16 *)(pInBuf + i)) * ((0 == (i % 2)) ? (u16)1 : (u16)3);
	}
	chkSum = (u16)(chkSum - oldChkSum);
	if (oldChkSum != chkSum) return XCRY_INVALID_CHECKSUM;

	return XCRY_OK;
}

/* INTERFACE */
int
xcry_data_metainfo(u8 *pInDecryptedBlock, sz_t szInDecryptedBlock, int *pOutDataType, sz_t *pOutSzData, sz_t *pOutNdxDataStart){
	XCryHead *pHead;
	if( NULL == pInDecryptedBlock || szInDecryptedBlock < sizeof(XCryHead) || NULL == pOutDataType || NULL == pOutSzData || NULL == pOutNdxDataStart)
		return XCRY_INVALID_INPUT;
	pHead = (XCryHead *)pInDecryptedBlock;

	*pOutDataType = pHead->dataType;
	*pOutSzData   = pHead->szData;
	*pOutNdxDataStart = pHead->szAlignLen + sizeof(XCryHead);
	
	return XCRY_OK;
}

