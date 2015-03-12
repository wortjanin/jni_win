#ifndef _UNIDBG_H_
#define _UNIDBG_H_

#include <string.h>

#define mdl_DECL \
  static char g_MDL_FILE_NAME[] = __FILE__; \
  static char *g_MODULE_NAME    = NULL

#define mdl_INI \
  g_MODULE_NAME_ini(&g_MODULE_NAME, g_MDL_FILE_NAME)

void g_MODULE_NAME_ini(char **moduleName, char fileName[]);

#define PRINT_BITS(LSTR, TYPE, X, RSTR) do{ \
    char b[sizeof(TYPE)*9]; \
	int i; \
	TYPE z; \
	b[sizeof(b) - 1] = '\0'; \
	for (z = 1, i = 0; i < sizeof(b) - 1; i++){ \
		if(0 == (i + 1)%9){ b[/* sizeof(b) - 2 - */ i] = ' '; continue; }  \
        b[/* sizeof(b) - 2 - */ i] = ((((TYPE)(X) & z) == z) ? '1' : '0'); \
		z <<= 1; \
	} \
	printf(LSTR "%s" RSTR, b); \
}while(0)


#ifdef DEBUG
	#define prnt(STRM ,FORMAT, ...)  \
		fprintf(STRM, "%s -> %s: " FORMAT, g_MODULE_NAME, __func__, ##__VA_ARGS__); \
		fflush(STRM)
#else 
	#define prnt(STRM ,FORMAT, ...)  \
		fprintf(STRM, "%s -> %s: " FORMAT, g_MODULE_NAME, __func__, ##__VA_ARGS__)
#endif /* DEBUG */


#define info(FORMAT, ...)  \
  prnt(stdout, FORMAT, ##__VA_ARGS__)

#define err(FORMAT, ...)  \
  prnt(stderr, FORMAT, ##__VA_ARGS__)


#ifdef DEBUG
/* Отладочные макросы (Замечание: НИКОГДА не помещайте важные вычисления в их параметры, т.к. они пропадут при релизе) */

#define ERRD(FORMAT, ...)  \
  prnt(stderr, FORMAT, ##__VA_ARGS__)

#define DNFO(FORMAT, ...) \
  info("dbg(%d): " FORMAT, __LINE__, ##__VA_ARGS__)

#define TRYD(WHAT, ERR_STRING, DO) \
  if(!(WHAT)){ ERRD ("test(%d) fail: %s\n",__LINE__, ERR_STRING); DO; }

#define ASRD(WHAT, DO) \
  TRYD(WHAT, #WHAT, DO)

#define ASRDBG(WHAT) \
  ASRD(WHAT, exit(FATAL_ERROR))

#else /* Напоминание: эти макросы ИСЧЕЗАЮТ */
#define ERRD(FORMAT, ...)
#define DNFO(FORMAT, ...)
#define TRYD(WHAT, ERR_STRING, DO)
#define ASRD(WHAT, DO)
#define ASRDBG(WHAT)
#endif /* DEBUG */

#define asrsys(WHAT, DO)                        \
  if(!(WHAT)){                                  \
    errno_info( errno );                        \
    info("fail(%d): %s\n", __LINE__, #WHAT);    \
    DO;                                         \
  }

#define asrstd(WHAT) asrsys(WHAT, goto fail)

#define asrm(WHAT, DO)                          \
  if(!(WHAT)){                                  \
    info("fail(%d): %s\n", __LINE__, #WHAT);    \
    DO;                                         \
  }

#define asrmstd(WHAT) asrm(WHAT, goto fail)

#define trysys(WHAT, FAIL_MSG)                  \
  if(!(WHAT)){                                  \
    errno_info( errno );                        \
    info("fail(%d): %s\n", __LINE__, FAIL_MSG); \
    goto fail;                                  \
  }

#define trmsys(WHAT, FAIL_MSG) trysys(0 <= (WHAT), FAIL_MSG )

#define trm(WHAT) trmsys(WHAT, #WHAT)

#define errno_info(err)                                           \
  /* if( 0 == strerror_s(err, try_DECL_buff, sizeof(try_DECL_buff)) ) { */ \
    info( "fail(%d): %d\n", __LINE__, err );            \
  /* } */


#define try_DECL                          \
  char try_DECL_buff[128]



#endif /* _UNIDBG_H_ */
