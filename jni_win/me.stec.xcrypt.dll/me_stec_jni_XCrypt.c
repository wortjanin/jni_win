#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "me_stec_jni_XCrypt.h"

#include "stecxcrypt.h"
#include "unitls.h"
#include "unithread.h"
 
#ifndef _NIX
#define JNICALL __cdecl
#endif

threads_IMPL;

void mtx_lock(void){
	pthread_mutex_lock(&g_mtx);
}

void mtx_unlock(){
	pthread_mutex_unlock(&g_mtx);
}


/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_cipher_get_algo_keylen(int eAlgo)
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1cipher_1get_1algo_1keylen
  (JNIEnv *env, jobject obj, jint eAlgo){
  return xcry_cipher_get_algo_keylen(eAlgo);
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_cipher_get_algo_blklen(int eAlgo)
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1cipher_1get_1algo_1blklen
  (JNIEnv *env, jobject obj, jint eAlgo){
  return  xcry_cipher_get_algo_blklen(eAlgo);
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    String xcry_error(int XCRY_CODE)
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_me_stec_jni_XCrypt_xcry_1error
  (JNIEnv *env, jobject obj, jint XCRY_CODE){
  return (*env)->NewStringUTF(env, xcry_error(XCRY_CODE));
}


/*
 * Class:     me_stec_jni_XCrypt
 * Method:    void xcry_ini()
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_me_stec_jni_XCrypt_xcry_1ini
  (JNIEnv *env, jobject obj){
	static int initialized = 0;
	mtx_lock();
	if(!initialized){
		//printf("Initializd!\n");
		initialized++;
		xcry_ini(mtx_lock, mtx_unlock);
	}
	mtx_unlock();
}


twk_inc_IMPL;
/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_open(int[] pFd, int eAlgo) 
 * C method:  int xcry_open(int* fd, EAlgo algo);
 * Signature: ([II)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1open
  (JNIEnv *env, jobject obj, jintArray pFd, jint eAlgo){
	int fd;
  jint *pFdRef;
  jint res = XCRY_OK;
  if ( 1 != (*env)->GetArrayLength(env, pFd) ) return XCRY_INVALID_INPUT; 
  if ( NULL == ( pFdRef = (*env)->GetIntArrayElements(env, pFd, NULL) ) ) return XCRY_ERROR;

  if( XCRY_OK == ( res = xcry_open(&fd, eAlgo) ) ) xcry_control(fd, XCRY_ECTR_3FISH_SET_TWK_INC, twk_inc);
  pFdRef[0] = (jint)fd;

  (*env)->ReleaseIntArrayElements(env, pFd, pFdRef, 0);
  return res;
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_close(int fd) 
 * C method:  int xcry_close(int fd)
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1close
  (JNIEnv *env, jobject obj, jint fd){
  return xcry_close(fd);
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_settwk(int fd, byte[] pTweak) 
 * C method:  int xcry_settwk(int fd, u8 *pTweak, sz_t szTweakLen)
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1settwk
  (JNIEnv *env, jobject obj, jint fd, jbyteArray pTweak){
  jsize szTweakLen;
  jbyte *pTweakRef;
  jint res;
  if ( NULL == ( pTweakRef = (*env)->GetByteArrayElements(env, pTweak, NULL) ) ) return XCRY_ERROR;

  szTweakLen = (*env)->GetArrayLength(env, pTweak);
  res = xcry_settwk(fd, (u8 *)pTweakRef, szTweakLen);

  (*env)->ReleaseByteArrayElements(env, pTweak, pTweakRef, 0);
  return res;
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_gettwk(int fd, byte[] pTweak) 
 * C method:  int xcry_gettwk(int fd, u8 **ppTweak)
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1gettwk
  (JNIEnv *env, jobject obj, jint fd, jbyteArray pTweak){
	jint res; 
	jbyte *pTweakRef;
	u8 *pNativeTweak;
	jsize szTweakLen;
  if ( 0 == ( szTweakLen = (*env)->GetArrayLength(env, pTweak) ) ) return XCRY_INVALID_LEN; 
  if ( NULL == ( pTweakRef = (*env)->GetByteArrayElements(env, pTweak, NULL) ) ) return XCRY_ERROR;
	
  res = xcry_gettwk(fd, &pNativeTweak);
  memcpy(pTweakRef, pNativeTweak, szTweakLen);
	//for(i = 0; i < szTweakLen; i++) pTweakRef[i] = (jbyte)(pNativeTweak[i]);

  (*env)->ReleaseByteArrayElements(env, pTweak, pTweakRef, 0);
  return res;
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_setkey(int fd, byte[] pKey) 
 * C method:  int xcry_setkey(int fd, u8 *pKey, sz_t szKeyLen)
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1setkey
  (JNIEnv *env, jobject obj, jint fd, jbyteArray pKey){
  jsize szKeyLen;
  jbyte *pKeyRef;
  jint res;
  if( NULL == ( pKeyRef = (*env)->GetByteArrayElements(env, pKey, NULL) ) ) return XCRY_ERROR;

  szKeyLen = (*env)->GetArrayLength(env, pKey);
  res = xcry_setkey(fd, (u8 *)pKeyRef, szKeyLen);

  (*env)->ReleaseByteArrayElements(env, pKey, pKeyRef, 0);
  return res;
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_encrypt(int fd, byte[] pInBuf, byte[] pOutBuf) 
 * C method:  int xcry_encrypt(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen)
 * Signature: (I[B[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1encrypt
  (JNIEnv *env, jobject obj, jint fd, jbyteArray pInBuf, jbyteArray pOutBuf){
  jsize szInBufLen, szOutBufLen;
  jbyte *pInBufRef, *pOutBufRef;
  jint res;
  if( NULL == ( pInBufRef  = (*env)->GetByteArrayElements(env, pInBuf, NULL) ) ) return XCRY_ERROR;
  if( NULL == ( pOutBufRef = (*env)->GetByteArrayElements(env, pOutBuf, NULL) ) ) { res = XCRY_ERROR; goto end; }


  szInBufLen  = (*env)->GetArrayLength(env, pInBuf);
  szOutBufLen = (*env)->GetArrayLength(env, pOutBuf);
  res = xcry_encrypt(fd, (u8 *)pInBufRef, szInBufLen, (u8 *)pOutBufRef, szOutBufLen);

  (*env)->ReleaseByteArrayElements(env, pOutBuf, pOutBufRef, 0);
end:
  (*env)->ReleaseByteArrayElements(env, pInBuf, pInBufRef, 0);
  return res;
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_decrypt(int fd, byte[] pInBuf, byte[] pOutBuf) 
 * C method:  int xcry_decrypt(int fd, u8 *pInBuf, sz_t szInBufLen, u8 *pOutBuf, sz_t szOutBufLen)
 * Signature: (I[B[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1decrypt
  (JNIEnv *env, jobject obj, jint fd, jbyteArray pInBuf, jbyteArray pOutBuf){
  jsize szInBufLen, szOutBufLen;
  jbyte *pInBufRef, *pOutBufRef;
  jint res;
  if( NULL == ( pInBufRef  = (*env)->GetByteArrayElements(env, pInBuf, NULL) ) ) return XCRY_ERROR;
  if( NULL == ( pOutBufRef = (*env)->GetByteArrayElements(env, pOutBuf, NULL) ) ) { res = XCRY_ERROR; goto end; }


  szInBufLen  = (*env)->GetArrayLength(env, pInBuf);
  szOutBufLen = (*env)->GetArrayLength(env, pOutBuf);
  res = xcry_decrypt(fd, (u8 *)pInBufRef, szInBufLen, (u8 *)pOutBufRef, szOutBufLen);

  (*env)->ReleaseByteArrayElements(env, pOutBuf, pOutBufRef, 0);
end:
  (*env)->ReleaseByteArrayElements(env, pInBuf, pInBufRef, 0);
  return res;
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_data_prepare(int eDataType, int szBlock, byte[] pInBuf, byte[] pOutBuf)
 * C method:  int xcry_data_prepare(EDataType eDataType, u16 szBlock, const u8 *pInBuf, u16 szInBuf, u8 *pOutBuf, u16 szOutBuf, u16 *pSzOutBuf)
 * Signature: (II[B[B[I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1data_1prepare
  (JNIEnv *env, jobject obj, jint eDataType, jint szBlock, jbyteArray pInBuf, jbyteArray pOutBuf, jintArray pSzOutBuf){
	u16 szOutBufResult;
  jsize szInBuf,    szOutBuf;
  jbyte *pInBufRef, *pOutBufRef;
  jint *pSzOutBufRef;
  jint res;
  static const jsize szMax = 65535;
  if ( 1 != (*env)->GetArrayLength(env, pSzOutBuf) ) return XCRY_INVALID_INPUT;
  if( NULL == ( pInBufRef  = (*env)->GetByteArrayElements(env, pInBuf, NULL) ) ) return XCRY_ERROR;
  if( NULL == ( pOutBufRef = (*env)->GetByteArrayElements(env, pOutBuf, NULL) ) ) { res = XCRY_ERROR; goto end_2; }
  if( NULL == ( pSzOutBufRef = (*env)->GetIntArrayElements(env, pSzOutBuf, NULL) ) ) { res = XCRY_ERROR; goto end_1; }
//	printf("%s\n", (const u8 *)pInBufRef);
  szInBuf  = (*env)->GetArrayLength(env, pInBuf);
  szOutBuf = (*env)->GetArrayLength(env, pOutBuf);
  if( szMax < szInBuf || szMax < szOutBuf || szMax < szBlock ) { res = XCRY_INVALID_LEN; goto end_0; }
//	printf("szBlock == %d szInBuf == %d szOutBuf == %d", (u16 )szBlock, (u16 )szInBuf, (u16 )szOutBuf );
  res = xcry_data_prepare(eDataType, (u16 )szBlock, (const u8 *)pInBufRef, (u16 )szInBuf, (u8 *)pOutBufRef, (u16 )szOutBuf, &szOutBufResult);
  if( XCRY_OK == res ) pSzOutBufRef[0] = szOutBufResult;

end_0:
  (*env)->ReleaseIntArrayElements(env,  pSzOutBuf, pSzOutBufRef, 0);
end_1:
  (*env)->ReleaseByteArrayElements(env, pOutBuf, pOutBufRef, 0);
end_2:
  (*env)->ReleaseByteArrayElements(env, pInBuf, pInBufRef, 0);
  return res;
}

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_data_check_first_block(byte[] pInBuf, int szBlock)
 * C method:  int xcry_data_check_first_block(const u8 *pInBuf, sz_t szBlock)
 * Signature: ([BI)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1data_1check_1first_1block
  (JNIEnv *env, jobject obj, jbyteArray pInBuf, jint szBlock){
  jbyte *pInBufRef;
  jint res;
  if ( (*env)->GetArrayLength(env, pInBuf) < szBlock ) return XCRY_INVALID_INPUT;
  if( NULL == ( pInBufRef  = (*env)->GetByteArrayElements(env, pInBuf, NULL) ) ) return XCRY_ERROR;

  res = xcry_data_check_first_block((const u8 *)pInBufRef, szBlock);

  (*env)->ReleaseByteArrayElements(env, pInBuf, pInBufRef, 0);
  return res;
}

//int xcry_data_metainfo(u8 *pInDecryptedBlock, sz_t szInDecryptedBlock, int *pOutDataType, sz_t *pOutSzData, sz_t *pOutNdxDataStart)
/*
 * Class:     me_stec_jni_XCrypt
 * Method:    int xcry_data_metainfo(byte[] pInDecryptedBlock, int[] pOutDataType, int[] pOutSzData, int[] pOutNdxDataStart)
 * C method:  int xcry_data_metainfo(u8 *pInDecryptedBlock, sz_t szInDecryptedBlock, int *pOutDataType, sz_t *pOutSzData, sz_t *pOutNdxDataStart)
 * Signature: ([B[I[I[I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1data_1metainfo
  (JNIEnv *env, jobject obj, jbyteArray pInDecryptedBlock, jintArray pOutDataType, jintArray pOutSzData, jintArray pOutNdxDataStart){
	jsize szInDecryptedBlock;
  jbyte *pInDecryptedBlockRef;
  jint res, *pOutDataTypeRef, *pOutSzDataRef, *pOutNdxDataStartRef;
	int dataType;
	sz_t szData, ndxDataStart;
	if ( 1 != (*env)->GetArrayLength(env, pOutDataType)    ||  
         1 != (*env)->GetArrayLength(env, pOutSzData)      ||
         1 != (*env)->GetArrayLength(env, pOutNdxDataStart)   ) return XCRY_INVALID_INPUT;
  if( NULL == ( pInDecryptedBlockRef = (*env)->GetByteArrayElements(env, pInDecryptedBlock, NULL) ) ) return XCRY_ERROR;
  if( NULL == ( pOutDataTypeRef = (*env)->GetIntArrayElements(env, pOutDataType, NULL) ) )         { res = XCRY_ERROR; goto end_2; }
  if( NULL == ( pOutSzDataRef = (*env)->GetIntArrayElements(env, pOutSzData, NULL) ) )             { res = XCRY_ERROR; goto end_1; }
  if( NULL == ( pOutNdxDataStartRef = (*env)->GetIntArrayElements(env, pOutNdxDataStart, NULL) ) ) { res = XCRY_ERROR; goto end_0; }

  szInDecryptedBlock = (*env)->GetArrayLength(env, pInDecryptedBlock);
  res =  xcry_data_metainfo((u8 *)pInDecryptedBlockRef, szInDecryptedBlock, &dataType, &szData, &ndxDataStart);
  if( XCRY_OK == res ){ pOutDataTypeRef[0] = (jint)dataType; pOutSzDataRef[0] = (jint)szData; pOutNdxDataStartRef[0] = (jint)ndxDataStart; }

  (*env)->ReleaseIntArrayElements(env,  pOutNdxDataStart,  pOutNdxDataStartRef, 0);
end_0:
  (*env)->ReleaseIntArrayElements(env,  pOutSzData,        pOutSzDataRef, 0);
end_1:
  (*env)->ReleaseIntArrayElements(env,  pOutDataType,      pOutDataTypeRef, 0);
end_2:
  (*env)->ReleaseByteArrayElements(env, pInDecryptedBlock, pInDecryptedBlockRef, 0);
  return res;
}



