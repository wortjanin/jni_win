#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "unitls.h"
#include "stecxcrypt_internal.h"

#include "unidbg.h"
static const XCryAlgo g_zeroXCryAlgo = { zeroXCryAlgo_INI };


#define ROR(X, SHIFT) \
	(((X) >> (SHIFT)) | ((X) << (sizeof(X)*8 - (SHIFT))))

#define ROL(X, SHIFT) \
	(((X) << (SHIFT)) | ((X) >> (sizeof(X)*8 - (SHIFT))))


#define MIXD(x0, x1, Y0, Y1, R) do{ \
	Y0 = (x0) + (x1); \
	Y1 = ROL((x1), (R)) ^ (Y0); \
} while(0)

/*
#define MIXR(y0, y1, X0, X1, R) do{ \
	X1 = ROR((y0) ^ (y1), (R)); \
	X0 = (y0) - (X1); \
} while(0)
*/

#define MIXR(y0, y1, X0, X1, R) do{ \
	X1 = (y0) ^ (y1); \
	X1 = ROR((X1), (R)); \
	X0 = (y0) - (X1); \
} while(0)

#define g_Rdj(SZ_BLK_BITS) G_RDJ_ ## SZ_BLK_BITS
static const u8 g_Rdj(256)[8][2] = {
	{ 14,	16 },
	{ 52,	57 },
	{ 23,	40 },
	{ 5,	37 },
	{ 25,	33 },
	{ 46,	12 },
	{ 58,	22 },
	{ 32,	32 }
};
static const  u8 g_Rdj(512)[8][4] = {
	{ 46,	36,	19,	37 },
	{ 33,	27,	14,	42 },
	{ 17,	49,	36,	39 },
	{ 44,	9,	54,	56 },
	{ 39,	30,	34,	24 },
	{ 13,	50,	10,	17 },
	{ 25,	29,	39,	43 },
	{ 8,	35,	56,	22 }
};
static const  u8 g_Rdj(1024)[8][8] = {
	{ 24,	13,	8,	47,	8,	17,	22,	37 },
	{ 38,	19,	10,	55,	49,	18,	23,	52 },
	{ 33,	4,	51,	13,	34,	41,	59,	17 },
	{ 5,	20,	48,	41,	47,	28,	16,	25 },
	{ 41,	9,	37,	31,	12,	47,	44,	30 },
	{ 16,	34,	56,	51,	4,	53,	42,	41 },
	{ 31,	44,	47,	46,	19,	42,	44,	25 },
	{ 9,	48,	35,	52,	23,	31,	37,	20 }
};

#define g_Pi(SZ_BLK_BITS) G_PI_ ## SZ_BLK_BITS
static const u8 g_Pi(256)[] = { 0, 3, 2, 1 };
static const u8 g_Pi(512)[] = { 2, 1, 4, 7, 6, 5, 0, 3 };
static const u8 g_Pi(1024)[] = { 0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1 };

static const u64 C240 = 0x1BD11BDAA9FC1A22LLU;

#define Nb(SZ_BLK_BITS) G_NB_ ## SZ_BLK_BITS
				#define G_NB_256	 32 /* 256 /8; */
				#define G_NB_512	 64 /* 512 /8; */
				#define G_NB_1024	128 /* 1024/8; */

#define Nw(SZ_BLK_BITS) G_NW_ ## SZ_BLK_BITS
				#define G_NW_256	 4 /* 256 /64; */
				#define G_NW_512	 8 /* 512 /64; */
				#define G_NW_1024	16 /* 1024/64; */

#define Nr(SZ_BLK_BITS) G_NR_ ## SZ_BLK_BITS
				#define G_NR_256	72
				#define G_NR_512	72
				#define G_NR_1024	80

#define KEY_MIX(SZ_BLK_BITS, SIGN) do{ \
	S = (d/4); \
	s = S % Nw1; \
	szShift = Nb(SZ_BLK_BITS) + (1 - s)*8; \
	memcpy(pData->k_buf.b, pData->key.b + s*8, szShift); \
	if(s > 0)	memcpy(pData->k_buf.b + szShift, pData->key.b, s*8); \
	pData->k_buf.w[Nw(SZ_BLK_BITS) - 3] += pData->tweak.t[S % 3]; \
	pData->k_buf.w[Nw(SZ_BLK_BITS) - 2] += pData->tweak.t[(S + 1) % 3]; \
	pData->k_buf.w[Nw(SZ_BLK_BITS) - 1] += S; \
	for(i = 0; i < Nw(SZ_BLK_BITS); i++) pOut64[i]	SIGN ## = pData->k_buf.w[i]; \
}while(0)

#define ENCRYPT_BLK(SZ_BLK_BITS) \
		memcpy(pOutBuf + iBlk, pInBuf + iBlk, Nb(SZ_BLK_BITS)); \
		pOut64 = (u64 *)(pOutBuf + iBlk); \
		for(d = 0; d < Nr(SZ_BLK_BITS); d++){ \
			if(0 == d % 4) KEY_MIX(SZ_BLK_BITS, +); /* key schedule, key apply */ \
			pRj = g_Rdj(SZ_BLK_BITS)[d % 8]; \
			for(j = 0; j < jMax; j += 2){/* MIX */ \
				sz_t j1 = j + 1; \
				MIXD(pOut64[j], pOut64[j1], pOut64[j], pOut64[j1], pRj[j/2]); \
			} \
			memcpy(pData->f_buf.b, pOut64, Nb(SZ_BLK_BITS)); \
			for(i = 0; i < Nw(SZ_BLK_BITS); i++) pOut64[i] = pData->f_buf.w[g_Pi(SZ_BLK_BITS)[i]]; /* permutation */ \
		} \
		KEY_MIX(SZ_BLK_BITS, +) 

#define DECRYPT_BLK(SZ_BLK_BITS) \
		memcpy(pOutBuf + iBlk, pInBuf + iBlk, Nb(SZ_BLK_BITS)); \
		pOut64 = (u64 *)(pOutBuf + iBlk); \
		d = Nr(SZ_BLK_BITS); \
		KEY_MIX(SZ_BLK_BITS, -); \
		for(d = Nr(SZ_BLK_BITS) - 1; d >=0; d--){ \
			memcpy(pData->f_buf.b, pOut64, Nb(SZ_BLK_BITS)); \
			for(i = 0; i < Nw(SZ_BLK_BITS); i++) pOut64[g_Pi(SZ_BLK_BITS)[i]] = pData->f_buf.w[i]; /* permutation */ \
			pRj = g_Rdj(SZ_BLK_BITS)[d % 8]; \
			for(j = 0; j < jMax; j += 2){/* MIX */ \
				sz_t j1 = j + 1; \
				MIXR(pOut64[j], pOut64[j1], pOut64[j], pOut64[j1], pRj[j/2]); \
			} \
			if(0 == d % 4) KEY_MIX(SZ_BLK_BITS, -); /* key schedule, key apply */ \
		}

#define FISH3_IMPL(SZ_BLK_BITS) \
typedef struct fish3_ ## SZ_BLK_BITS fish3_ ## SZ_BLK_BITS; \
struct fish3_ ## SZ_BLK_BITS{ \
	  fish3_twk_inc fp_twk_inc; \
		void *pUsrBuf; \
		union{ \
			u64 t[3]; \
			u8  b[24]; \
		}tweak; \
		union{ \
			u64 k[Nw(SZ_BLK_BITS) + 1]; \
			u8	b[Nb(SZ_BLK_BITS) + 8]; \
		} key; \
		union{ \
			u64 w[Nw(SZ_BLK_BITS)]; \
			u8  b[Nb(SZ_BLK_BITS)]; \
		}f_buf; \
		union{ \
			u64 w[Nw(SZ_BLK_BITS) + 1]; \
			u8  b[Nb(SZ_BLK_BITS) + 8]; \
		}k_buf; \
}; \
ERes \
xcry_3fish ## SZ_BLK_BITS ## _settwk(XCryAlgo *pAlgo, u8 *pTweak, sz_t szTweakLen){ \
	fish3_ ## SZ_BLK_BITS  *pData; \
	if(16 != szTweakLen) return XCRY_INVALID_LEN; \
	if(NULL == pAlgo || NULL == (pData = ((fish3_ ## SZ_BLK_BITS *)(pAlgo->pData))) || NULL == pTweak) return XCRY_INVALID_INPUT; \
\
	memcpy(pData->tweak.b, pTweak, szTweakLen); \
	pData->tweak.t[2] = pData->tweak.t[0] ^ pData->tweak.t[1]; \
	return XCRY_OK; \
} \
ERes \
xcry_3fish ## SZ_BLK_BITS ## _gettwk(XCryAlgo *pAlgo, u8 **ppTweak){ \
	fish3_ ## SZ_BLK_BITS  *pData; \
	if(NULL == pAlgo || NULL == (pData = ((fish3_ ## SZ_BLK_BITS *)(pAlgo->pData))) ) return XCRY_INVALID_INPUT; \
\
	*ppTweak = pData->tweak.b; \
	return XCRY_OK; \
} \
ERes xcry_3fish ## SZ_BLK_BITS ## _setkey(XCryAlgo *pAlgo, u8 *pKey, sz_t szKeyLen){ \
	sz_t i; \
	fish3_ ## SZ_BLK_BITS *pData; \
	if(Nb(SZ_BLK_BITS) != szKeyLen) return XCRY_INVALID_LEN; \
	if(NULL == pAlgo || NULL == (pData = ((fish3_ ## SZ_BLK_BITS *)(pAlgo->pData))) || NULL == pKey) return XCRY_INVALID_INPUT; \
\
	memcpy(pData->key.b, pKey, szKeyLen); \
	pData->key.k[Nw(SZ_BLK_BITS)] = C240; \
	for(i = 0; i < Nw(SZ_BLK_BITS); i++) \
		pData->key.k[Nw(SZ_BLK_BITS)] ^= pData->key.k[i]; \
\
	return XCRY_OK; \
} \
ERes \
xcry_3fish ## SZ_BLK_BITS ## _encrypt(XCryAlgo *pAlgo, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){ \
	fish3_ ## SZ_BLK_BITS *pData; \
	u64 *pOut64; \
	int d; \
	sz_t j, i, s, S, szShift, iBlk; \
	const sz_t jMax = Nw(SZ_BLK_BITS)/2 + 1, Nw1 = Nw(SZ_BLK_BITS) + 1; \
	const u8 *pRj; \
	if(!(szInBufLen > 0 && 0 == (szInBufLen % Nb(SZ_BLK_BITS)) && szInBufLen == szOutBufLen)) return XCRY_INVALID_LEN; \
	if( NULL == pAlgo  || NULL == (pData = ((fish3_ ## SZ_BLK_BITS *)(pAlgo->pData))) ) return XCRY_INVALID_INPUT; \
	if( NULL == pInBuf || NULL == pOutBuf ) return XCRY_INVALID_INPUT; \
	for(iBlk = 0; iBlk < szInBufLen; iBlk += Nb(SZ_BLK_BITS)){ \
		ENCRYPT_BLK(SZ_BLK_BITS); \
	}	\
	return XCRY_OK; \
}  \
ERes \
xcry_3fish ## SZ_BLK_BITS ## _encrypt_with_twk_inc(XCryAlgo *pAlgo, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){ \
	fish3_ ## SZ_BLK_BITS *pData; \
	u64 *pOut64; \
	int d; \
	sz_t j, i, s, S, szShift, iBlk; \
	const sz_t jMax = Nw(SZ_BLK_BITS)/2 + 1, Nw1 = Nw(SZ_BLK_BITS) + 1; \
	const u8 *pRj; \
	if(!(szInBufLen > 0 && 0 == (szInBufLen % Nb(SZ_BLK_BITS)) && szInBufLen == szOutBufLen)) return XCRY_INVALID_LEN; \
	if( NULL == pAlgo  || NULL == (pData = ((fish3_ ## SZ_BLK_BITS *)(pAlgo->pData))) ) return XCRY_INVALID_INPUT; \
	if( NULL == pInBuf || NULL == pOutBuf ) return XCRY_INVALID_INPUT; \
	for(iBlk = 0; iBlk < szInBufLen; iBlk += Nb(SZ_BLK_BITS)){ \
		ENCRYPT_BLK(SZ_BLK_BITS); \
		((fish3_## SZ_BLK_BITS *)(pAlgo->pData))->fp_twk_inc(pData->tweak.t); \
	}	\
	return XCRY_OK; \
} \
ERes \
xcry_3fish ## SZ_BLK_BITS ## _decrypt(XCryAlgo *pAlgo, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){ \
	fish3_## SZ_BLK_BITS *pData; \
	u64 *pOut64; \
	int d; \
	sz_t i, j, s, S, szShift, iBlk; \
	const sz_t jMax = Nw(SZ_BLK_BITS)/2 + 1, Nw1 = Nw(SZ_BLK_BITS) + 1; \
	const u8 *pRj; \
	if(!(szInBufLen > 0 && 0 == (szInBufLen % Nb(SZ_BLK_BITS)) && szInBufLen == szOutBufLen)) return XCRY_INVALID_LEN; \
	if( NULL == pAlgo  || NULL == (pData = ((fish3_ ## SZ_BLK_BITS *)(pAlgo->pData))) ) return XCRY_INVALID_INPUT; \
	if( NULL == pInBuf || NULL == pOutBuf ) return XCRY_INVALID_INPUT; \
\
	for(iBlk = 0; iBlk < szInBufLen; iBlk += Nb(SZ_BLK_BITS)){ \
		DECRYPT_BLK(SZ_BLK_BITS); \
	} \
	return XCRY_OK; \
} \
ERes \
xcry_3fish ## SZ_BLK_BITS ## _decrypt_with_twk_inc(XCryAlgo *pAlgo, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen){ \
	fish3_## SZ_BLK_BITS *pData; \
	u64 *pOut64; \
	int d; \
	sz_t i, j, s, S, szShift, iBlk; \
	const sz_t jMax = Nw(SZ_BLK_BITS)/2 + 1, Nw1 = Nw(SZ_BLK_BITS) + 1; \
	const u8 *pRj; \
	if(!(szInBufLen > 0 && 0 == (szInBufLen % Nb(SZ_BLK_BITS)) && szInBufLen == szOutBufLen)) return XCRY_INVALID_LEN; \
	if( NULL == pAlgo  || NULL == (pData = ((fish3_ ## SZ_BLK_BITS *)(pAlgo->pData))) ) return XCRY_INVALID_INPUT; \
	if( NULL == pInBuf || NULL == pOutBuf ) return XCRY_INVALID_INPUT; \
\
	for(iBlk = 0; iBlk < szInBufLen; iBlk += Nb(SZ_BLK_BITS)){ \
		DECRYPT_BLK(SZ_BLK_BITS); \
		((fish3_## SZ_BLK_BITS *)(pAlgo->pData))->fp_twk_inc(pData->tweak.t); \
	} \
	return XCRY_OK; \
} \
ERes \
xcry_3fish ## SZ_BLK_BITS ## _close(XCryAlgo *pAlgo){ \
	freeX(pAlgo->pData); \
	pAlgo->iAlgo = NULL; \
	return XCRY_OK; \
} \
ERes  \
xcry_3fish ## SZ_BLK_BITS ## _control(XCryAlgo *pAlgo, ECtr eCtl, void *pData); \
static const IXCryAlgo g_IAlgo ## SZ_BLK_BITS = { iXCryAlgo_INI(xcry_3fish ## SZ_BLK_BITS) }; \
static const IXCryAlgo g_IAlgo_wTWKINC ## SZ_BLK_BITS = { iXCryAlgo_INI_wTWKINC(xcry_3fish ## SZ_BLK_BITS) }; \
ERes  \
xcry_3fish ## SZ_BLK_BITS ## _control(XCryAlgo *pAlgo, ECtr eCtl, void *pData){ \
	switch(eCtl){ \
		case XCRY_ECTR_3FISH_SET_TWK_INC: { \
			fish3_## SZ_BLK_BITS *pAlgoData = ((fish3_## SZ_BLK_BITS *)(pAlgo->pData)); \
			pAlgoData->fp_twk_inc = (fish3_twk_inc)pData; \
			pAlgo->iAlgo = (NULL == pData)?(&g_IAlgo ## SZ_BLK_BITS):(&g_IAlgo_wTWKINC ## SZ_BLK_BITS); \
			return XCRY_OK; } \
		case XCRY_ECTR_3FISH_SET_USR_BUF: { \
			((fish3_## SZ_BLK_BITS *)(pAlgo->pData))->pUsrBuf = pData; \
			return XCRY_OK; } \
		case XCRY_ECTR_3FISH_GET_USR_BUF: { \
			*((void **)(pData)) = ((fish3_## SZ_BLK_BITS *)(pAlgo->pData))->pUsrBuf; \
			return XCRY_OK; } \
		default: break; \
	}  \
	return XCRY_INVALID_INPUT; \
} \
ERes  \
xcry_3fish ## SZ_BLK_BITS ## _open(XCryAlgo *pAlgo){ \
	fish3_## SZ_BLK_BITS *pAlgoData; \
	if( NULL == ( pAlgo->pData = malloc(sizeof(fish3_ ## SZ_BLK_BITS)) ) ) return XCRY_NOMEM; \
 \
	pAlgoData = (fish3_## SZ_BLK_BITS *)(pAlgo->pData); \
	pAlgoData->fp_twk_inc = NULL; \
	pAlgoData->pUsrBuf = NULL; \
	pAlgo->iAlgo = &g_IAlgo ## SZ_BLK_BITS; \
	return XCRY_OK; \
} 

/* /////////////////////////////////////////////////////////// */

FISH3_IMPL(256);
FISH3_IMPL(512);
FISH3_IMPL(1024);

ERes xcry_3fish_open(XCryAlgo *pAlgo, EAlgo algo){
	if(NULL != pAlgo->pData) return XCRY_INVALID_INPUT;
	switch(algo){
		case XCRY_EALGO_3FISH256: return xcry_3fish256_open(pAlgo);
		case XCRY_EALGO_3FISH512: return xcry_3fish512_open(pAlgo);
		case XCRY_EALGO_3FISH1024: return xcry_3fish1024_open(pAlgo);
		default: break;
	}
	return XCRY_INVALID_ALGORITHM;
}

