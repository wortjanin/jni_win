#ifndef _STECXCRYPT_H_
#define _STECXCRYPT_H_

#include "unitypes.h"

typedef enum EnumRes{
  XCRY_OK = 0, /* XCRY_OK must be zero */
  XCRY_ERROR,
  XCRY_INVALID_ALGORITHM,
  XCRY_NOMEM,
  XCRY_INVALID_INPUT,
  XCRY_INVALID_LEN,
  XCRY_INVALID_BUFLEN,
  XCRY_INVALID_CHECKSUM
}ERes;
#define xcry_error_IMPL \
  const char * xcry_error(int XCRY_CODE){ \
    switch(XCRY_CODE){ \
      case XCRY_OK: return "No errors!"; \
      case XCRY_ERROR: return "Undefined error."; \
      case XCRY_INVALID_ALGORITHM: return "Invalid algorythm."; \
      case XCRY_NOMEM: return "No memory."; \
      case XCRY_INVALID_INPUT: return "Invalid input."; \
      case XCRY_INVALID_LEN: return "Invalid length."; \
      case XCRY_INVALID_BUFLEN: return "Invalid buffer length."; \
      case XCRY_INVALID_CHECKSUM: return "Invalid check sum."; \
      default: break; \
    } \
    return "Unknown error (probably invalid input XCRY_CODE is passed to xcry_error function)."; \
  }

typedef enum EnumDataType{
	DATA = 0
} EDataType;

typedef enum EnumAlgo{
	XCRY_EALGO_3FISH256		= 0,
	XCRY_EALGO_3FISH512		= 1,
	XCRY_EALGO_3FISH1024	= 2
}EAlgo;

typedef enum EnumAlgoControl{
	XCRY_ECTR_3FISH_SET_TWK_INC	= 0, /* if you set fish3_twk_inc, do not forget to reset tweak before EACH encrypt/decrypt call */
	XCRY_ECTR_3FISH_SET_USR_BUF = 1,
	XCRY_ECTR_3FISH_GET_USR_BUF = 2  
}ECtr;
typedef void (*fish3_twk_inc)(u64 *aTwk3); 
#define twk_inc_IMPL \
	void twk_inc(u64 *aTwk3){ \
		u64 aTwk3_0 = aTwk3[0]++; \
		aTwk3[1] += (aTwk3_0 % 2)?-aTwk3_0:aTwk3_0; \
		aTwk3[2] = aTwk3[0] ^ aTwk3[1]; \
	}


typedef void (*xcry_mutex_callback)(void);

/**	
 *	Open and close operations are sinchronized only
 *
 *	Usually, you need to operate under an opened descripor in one thread 
 *		(but you can use other threads for other descriptors at the same time),
 *		however, if you are going to operate under the same descriptor from different threads,
 *		you should synchronize these cases yourself.
 *
 *	if mutex_cb_lock or mutex_cb_unlock are NULL, no sinchronization is performed.
 */
void
xcry_ini(xcry_mutex_callback mutex_cb_lock,  xcry_mutex_callback mutex_cb_unlock);
void
xcry_release(void);

sz_t
xcry_cipher_get_algo_keylen(EAlgo algo);

sz_t
xcry_cipher_get_algo_blklen(EAlgo algo);


const char * xcry_error(int XCRY_CODE); /* XCRY_CODE == code returned by xcry_open, xcry_close ..., if XCRY_CODE == 0 everything is 0k. */
int
xcry_open(int* fd, EAlgo algo);
int
xcry_close(int fd);

int
xcry_control(int fd, ECtr eCtl, void *pData);


int 
xcry_settwk(int fd, u8 *pTweak, sz_t szTweakLen);
int
xcry_gettwk(int fd, u8 **ppTweak);


int 
xcry_setkey(int fd, u8 *pKey, sz_t szKeyLen);

int 
xcry_encrypt(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen);

int
xcry_decrypt(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen);

/* XCryHead: is used by xcry_data_prepare, xcry_data_check_first_block */
typedef struct XCryHead XCryHead;
struct XCryHead{
	u16		szData;
	u8		dataType;
	u8		szAlignLen;
	u16		chkSum;
	u16		randNum;
};
#define zeroXCryHead_INI \
	0, \
	0, \
	0, \
	0, \
	0  
/* xcry_data_prepare: pInBuf and pOutBuf can point to the same buffer */
int
xcry_data_prepare(EDataType eDataType, u16 szBlock, const u8 *pInBuf, u16 szInBuf, u8 *pOutBuf, u16 szOutBuf, u16 *pSzOutBuf);
int
xcry_data_check_first_block(const u8 *pInBuf, sz_t szBlock);
int
xcry_data_metainfo(u8 *pInDecryptedBlock, sz_t szInDecryptedBlock, int *pOutDataType, sz_t *pOutSzData, sz_t *pOutNdxDataStart);

#endif /* _STECXCRYPT_H_ */

