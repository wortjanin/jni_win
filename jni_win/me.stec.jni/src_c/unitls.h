#ifndef _UNITLS_H_
#define _UNITLS_H_

#include "unitypes.h"

#define mallocX(PTR, SZ_ARR) \
  PTR = malloc((SZ_ARR) * sizeof(*(PTR)))

#define mallocXX(PP, I, SZ_BUF) \
  *((PP) + (I)) = malloc((SZ_BUF) * sizeof(**(PP)))

#define freeX(PTR) if(NULL != (PTR)){ free(PTR); (PTR) = NULL; }


#define ringBuf_DECL(SZ_TYPE, ARR_OF_PTRS) \
	SZ_TYPE     ARR_OF_PTRS ## _numEdge;   \
	SZ_TYPE     ARR_OF_PTRS ## _numFirst;  \
	SZ_TYPE     ARR_OF_PTRS ## _numLast;   \
	SZ_TYPE    *ARR_OF_PTRS ## _aNumFree

#define ringBuf_INI(ARR_OF_PTRS)              \
  /* .ARR_OF_PTRS ## _numEdge   = */ 0,       \
  /* .ARR_OF_PTRS ## _numFirst  = */ 0,       \
  /* .ARR_OF_PTRS ## _numLast   = */ 0,       \
  /* .ARR_OF_PTRS ## _aNumFree  = */ NULL     \

#define ringBuf_aNumFree_IMPL(PTR, ARR_OF_PTRS) \
  ( (PTR)->ARR_OF_PTRS ## _aNumFree )

#define ringBuf_szof_IMPL(PTR, ARR_OF_PTRS)  \
  sizeof(*( (PTR)->ARR_OF_PTRS ## _aNumFree ))

#define ringBuf_sz_IMPL(PTR, ARR_OF_PTRS, SZ_ARR_OF_PTRS) \
  ((SZ_ARR_OF_PTRS) * ringBuf_szof_IMPL(PTR, ARR_OF_PTRS))

#define  ringBuf_numEdge_IMPL(PTR, ARR_OF_PTRS) \
  ((PTR)->ARR_OF_PTRS ## _numEdge)

// if ringBuf is Full we can not pop from it FreeNums
#define ringBuf_isFull_IMPLX(PTR, ARR_OF_PTRS, SZ_ARR_OF_PTRS) \
  ( ((PTR)->ARR_OF_PTRS ## _numLast == (PTR)->ARR_OF_PTRS ## _numFirst ) && (((PTR)->ARR_OF_PTRS ## _numEdge) == SZ_ARR_OF_PTRS) )

#define  ringBuf_popFreeNum_IMPLX(NEXT_FREE_NUM, PTR, ARR_OF_PTRS, SZ_ARR_OF_PTRS, DBG_ERR_DO) \
  if((PTR)->ARR_OF_PTRS ## _numFirst  == (PTR)->ARR_OF_PTRS ## _numLast){ \
    ASRD( ((PTR)->ARR_OF_PTRS ## _numEdge) < SZ_ARR_OF_PTRS, DBG_ERR_DO); \
    NEXT_FREE_NUM = ((PTR)->ARR_OF_PTRS ## _numEdge)++; \
  } \
  else{ \
    NEXT_FREE_NUM = (PTR)->ARR_OF_PTRS ## _aNumFree [((PTR)->ARR_OF_PTRS ## _numFirst )++]; \
    if(((PTR)->ARR_OF_PTRS ## _numFirst ) == SZ_ARR_OF_PTRS) (PTR)->ARR_OF_PTRS ## _numFirst  = 0;/* кольцевой буфер */ \
  }

#define ringBuf_pushFreeNum_IMPLX(PTR, NUM_OF_RELEASED_ITEM, ARR_OF_PTRS, SZ_ARR_OF_PTRS) \
 do{ \
  (PTR)->ARR_OF_PTRS ## _aNumFree [(PTR)->ARR_OF_PTRS ## _numLast ++] = NUM_OF_RELEASED_ITEM; \
  if( (PTR)->ARR_OF_PTRS ## _numLast == SZ_ARR_OF_PTRS )    (PTR)->ARR_OF_PTRS ## _numLast = 0; /* кольцевой буфер */ \
 }while(0)

//as ringBuf becomes full of free nums (right after pushFreeNum), we should set ringBuf_numEdge_IMPL(PTR, ARR_OF_PTRS) to 0, after what  we can pop again
#define ringBuf_isFullOfFreeNum_IMPLX(PTR, ARR_OF_PTRS) \
  ((PTR)->ARR_OF_PTRS ## _numLast == (PTR)->ARR_OF_PTRS ## _numFirst )

#define ringBuf_pushFreeNum_IMPLX2(PTR, NUM_OF_RELEASED_ITEM, ARR_OF_PTRS, SZ_ARR_OF_PTRS)  \
	do{ \
	 ringBuf_pushFreeNum_IMPLX(PTR, NUM_OF_RELEASED_ITEM, ARR_OF_PTRS, SZ_ARR_OF_PTRS); \
	 if( ringBuf_isFullOfFreeNum_IMPLX(PTR, ARR_OF_PTRS) ) \
			ringBuf_numEdge_IMPL(PTR, ARR_OF_PTRS) = 0; \
	}while(0)



void
memptrset(void* dst, const void* src, sz_t szSrc, sz_t times);

#endif /* _UNITLS_H_ */

