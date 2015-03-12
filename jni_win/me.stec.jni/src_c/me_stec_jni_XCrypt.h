/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class me_stec_jni_XCrypt */

#ifndef _Included_me_stec_jni_XCrypt
#define _Included_me_stec_jni_XCrypt
#ifdef __cplusplus
extern "C" {
#endif
#undef me_stec_jni_XCrypt_XCRY_EALGO_3FISH256
#define me_stec_jni_XCrypt_XCRY_EALGO_3FISH256 0L
#undef me_stec_jni_XCrypt_XCRY_EALGO_3FISH512
#define me_stec_jni_XCrypt_XCRY_EALGO_3FISH512 1L
#undef me_stec_jni_XCrypt_XCRY_EALGO_3FISH1024
#define me_stec_jni_XCrypt_XCRY_EALGO_3FISH1024 2L
#undef me_stec_jni_XCrypt_XCRY_EDATA_TYPE_DATA
#define me_stec_jni_XCrypt_XCRY_EDATA_TYPE_DATA 0L
#undef me_stec_jni_XCrypt_SZ_BUF_MAX
#define me_stec_jni_XCrypt_SZ_BUF_MAX 65535L

#ifndef _NIX
#define JNICALL __cdecl
#endif

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_cipher_get_algo_keylen
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1cipher_1get_1algo_1keylen
  (JNIEnv *, jobject, jint);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_cipher_get_algo_blklen
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1cipher_1get_1algo_1blklen
  (JNIEnv *, jobject, jint);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_error
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_me_stec_jni_XCrypt_xcry_1error
  (JNIEnv *, jobject, jint);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_ini
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_me_stec_jni_XCrypt_xcry_1ini
  (JNIEnv *, jobject);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_open
 * Signature: ([II)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1open
  (JNIEnv *, jobject, jintArray, jint);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1close
  (JNIEnv *, jobject, jint);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_settwk
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1settwk
  (JNIEnv *, jobject, jint, jbyteArray);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_gettwk
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1gettwk
  (JNIEnv *, jobject, jint, jbyteArray);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_setkey
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1setkey
  (JNIEnv *, jobject, jint, jbyteArray);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_encrypt
 * Signature: (I[B[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1encrypt
  (JNIEnv *, jobject, jint, jbyteArray, jbyteArray);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_decrypt
 * Signature: (I[B[B)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1decrypt
  (JNIEnv *, jobject, jint, jbyteArray, jbyteArray);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_data_prepare
 * Signature: (II[B[B[I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1data_1prepare
  (JNIEnv *, jobject, jint, jint, jbyteArray, jbyteArray, jintArray);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_data_check_first_block
 * Signature: ([BI)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1data_1check_1first_1block
  (JNIEnv *, jobject, jbyteArray, jint);

/*
 * Class:     me_stec_jni_XCrypt
 * Method:    xcry_data_metainfo
 * Signature: ([B[I[I[I)I
 */
JNIEXPORT jint JNICALL Java_me_stec_jni_XCrypt_xcry_1data_1metainfo
  (JNIEnv *, jobject, jbyteArray, jintArray, jintArray, jintArray);

#ifdef __cplusplus
}
#endif
#endif