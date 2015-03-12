#include <string.h>

#include "unitls.h"

void
memptrset(void* dst, const void* src, sz_t szSrc, sz_t times){
  u64 ndx, head, head2, szTotal;
  if(0 == times || 0 == szSrc) return;
/* FIXME: handle possible arythmetic overflows */
  szTotal = times*szSrc; /* overflow1 on input */

  memcpy(dst, src, szSrc);
  for(ndx = szSrc, head = szSrc; ndx <  szTotal; ){
    memcpy((u8 *)dst + ndx, dst, head);
    ndx += head;
    head2 = 2*head; /* overflow2 */
    if(head2 < szTotal - head2)
      head  = head2;
    else
      head = szTotal - ndx;
  }
/*
  for(i = 0, ptr = dst; i < times; i++, ptr += szSrc){
    memcpy(ptr, src, szSrc);
  }
*/
}

