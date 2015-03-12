#ifndef _UNITHREAD_H_
#define _UNITHREAD_H_

#ifndef _NIX

#include <Windows.h>

#define threads_IMPL \
	typedef CRITICAL_SECTION pthread_mutex_t; \
	static int pthread_mutex_lock(pthread_mutex_t *pMtx) \
	{ \
		EnterCriticalSection(pMtx); \
		return 0; \
	} \
  \
	static int pthread_mutex_unlock(pthread_mutex_t *pMtx) \
	{	\
		LeaveCriticalSection(pMtx); \
		return 0; \
	} \
  \
  static pthread_mutex_t g_mtx; \
	BOOL APIENTRY DllMain (HINSTANCE hInst, DWORD reason, LPVOID lpReserved) \
	{ \
	 static int loaded = 0; \
   switch (reason) \
   { \
     case DLL_PROCESS_ATTACH: \
			 if(!loaded){ loaded++; InitializeCriticalSection(&g_mtx); } /* DeleteCriticalSection(&g_mtx); */ \
       break; \
     case DLL_PROCESS_DETACH: \
       break; \
     case DLL_THREAD_ATTACH: \
       break; \
     case DLL_THREAD_DETACH: \
       break; \
   } \
   return TRUE; \
	}

#else

#include <pthread.h>

#define threads_IMPL \
	static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER 

#endif

#endif /* _UNITHREAD_H_ */
