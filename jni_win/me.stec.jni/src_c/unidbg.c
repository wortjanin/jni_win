#include <string.h>
#include "unidbg.h"

void g_MODULE_NAME_ini(char **moduleName, char fileName[]){
  char *pcNoExt, *sName;

  if(*moduleName) return;

  sName = strrchr( fileName,  '/');
  sName = (sName ? (sName + 1) : fileName);

  pcNoExt = strrchr( sName, '.');
  if(pcNoExt) *pcNoExt = '\0';

  *moduleName = sName;
}
