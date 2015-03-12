#ifndef _STECXCRYPT_INTERNAL_
#define _STECXCRYPT_INTERNAL_

#include "stecxcrypt.h"


typedef struct XCryAlgo XCryAlgo;
typedef ERes (* xcry_iclose)(XCryAlgo *pAlgo);
typedef ERes (* xcry_icontrol)(XCryAlgo *pAlgo, ECtr eCtl, void *pData);
typedef ERes (* xcry_isettwk)(XCryAlgo *pAlgo, u8 *pTweak, sz_t szTweakLen);
typedef ERes (* xcry_igettwk)(XCryAlgo *pAlgo, u8 **ppTweak);
typedef ERes (* xcry_isetkey)(XCryAlgo *pAlgo, u8 *pKey, sz_t szKeyLen);
typedef ERes (* xcry_icrypt)(XCryAlgo *pAlgo, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen);
typedef struct IXCryAlgo IXCryAlgo;
struct IXCryAlgo{
	xcry_iclose		fp_close;

	xcry_icontrol	fp_control;

	xcry_isettwk	fp_settwk;
	xcry_igettwk	fp_gettwk;

	xcry_isetkey	fp_setkey;

	xcry_icrypt		fp_encrypt;
	xcry_icrypt		fp_decrypt;
};
#define iXCryAlgo_INI(PREFIX)   \
	PREFIX ## _close,           \
                                \
	PREFIX ## _control,         \
	                            \
	PREFIX ## _settwk,          \
	PREFIX ## _gettwk,          \
	                            \
	PREFIX ## _setkey,          \
	                            \
	PREFIX ## _encrypt,         \
	PREFIX ## _decrypt
#define iXCryAlgo_INI_wTWKINC(PREFIX)   \
	PREFIX ## _close,                   \
                                        \
	PREFIX ## _control,                 \
	                                    \
	PREFIX ## _settwk,                  \
	PREFIX ## _gettwk,                  \
	                                    \
	PREFIX ## _setkey,                  \
	                                    \
	PREFIX ## _encrypt_with_twk_inc,    \
	PREFIX ## _decrypt_with_twk_inc


struct XCryAlgo{
	const IXCryAlgo *iAlgo;

	void		    *pData;
};
#define zeroXCryAlgo_INI   \
	/* .iAlgo	= */ NULL, \
                           \
	/* .pData	= */ NULL

/* note: 3fish is implemented only for little-endian byte order (which is usual for x86, x86-64) */
ERes 
xcry_3fish_open(XCryAlgo *pAlgo, EAlgo algo);

ERes
xcry_3fish_ini_control(ECtr eCtl, void *pData);

#endif /* _STECXCRYPT_INTERNAL_ */

