/* minimaler test: ausgabe der slot und token label */

#include "cryptoki.h"
#include <stdio.h>
#include <stdlib.h>


/* {{{ int read_statistics */
#define GT_OBJ_TYPE_NUM 6

static char* object_labels[GT_OBJ_TYPE_NUM] = {
  "data",
  "certificate",
  "pubclic key",
  "private key",
  "secret key",
  "hardware feature" 
};

CK_RV display_token_info(CK_FUNCTION_LIST_PTR pFunctionList,CK_ULONG slotId)
{
  CK_RV rv = CKR_OK;
  CK_TOKEN_INFO token_info;

  rv = (pFunctionList->C_GetTokenInfo)(slotId,&token_info);
  if(rv != CKR_OK)
    {
      printf("GetTokenInfo failed: 0x%08x",rv);
      return rv;
    }


  printf("Slot %d: Token Information\n",slotId);
  printf("\t Token Label: \t%.32s\n", token_info.label);
  printf("\t Token Model: \t%.16s\n", token_info.model);
  printf("\t Token Firmware: \t%d.%d\n", 
	 token_info.firmwareVersion.major,
	 token_info.firmwareVersion.minor);
  
  return CKR_OK;
}

CK_RV read_statistic(CK_ULONG session,CK_FUNCTION_LIST_PTR pFunctionList, 
		    CK_ULONG slotId)
{
  CK_RV rv = CKR_OK;
  unsigned int i;
  static CK_ATTRIBUTE template;
  CK_ULONG count;
  CK_ULONG retcount;	
  
  for(i=0;i<GT_OBJ_TYPE_NUM;i++)
    {
      template.type = CKA_CLASS;
      template.pValue = &i;
      template.ulValueLen = sizeof(i);
      
      count=0;

      rv = (pFunctionList->C_FindObjectsInit)(session,&template,1);
      if(rv != CKR_OK)
	{
	  printf("could not init FindObj for Type 0x%08x: 0x%08x",i,rv);
	  return rv;
	}
      
      do {
	CK_OBJECT_HANDLE handle_hold;
	rv = (pFunctionList->C_FindObjects)(session,&handle_hold,
					    1,&retcount);
	if(rv != CKR_OK)
	  {
	    printf("FindObj failed: 0x%08x",i,rv);
	    return rv;
	  }

	count+=retcount;
      } while(retcount == 1);
      
      rv = (pFunctionList->C_FindObjectsFinal)(session);
      if(rv != CKR_OK)
	{
	  printf("FindObjFinal failed: 0x%08x",i,rv);
	  return rv;
	}
      
      printf("there are %i %s objects on token %i\n", 
	     count,object_labels[i], slotId);
      
    }

  return rv;
}
/* }}} */

/* {{{ int main */
int main()
{
  CK_FUNCTION_LIST_PTR pFunctionList;
  CK_RV rv = CKR_OK;
  
  rv = C_GetFunctionList(&pFunctionList);
  if(rv != CKR_OK)
    {
      printf("could not get function pointer list: %d",rv);
      exit(1);
    }
  
  rv = (pFunctionList->C_Initialize)(NULL_PTR);
  if(rv != CKR_OK)
    {
      printf("could not initialize: %d",rv);
      exit(1);
    }
  
  /* get the slot list */	
  {
    CK_ULONG ulSlotCount;
    CK_SLOT_ID_PTR pSlotList;
    int i;

    rv = (pFunctionList->C_GetSlotList)(TRUE,NULL_PTR,&ulSlotCount);
    if(rv != CKR_OK)
      {
	printf("could not get slot count: %d",rv);
	exit(1);
      }
    printf("GetSlotList: %d slots with token, ",ulSlotCount);

    rv = (pFunctionList->C_GetSlotList)(FALSE,NULL_PTR,&ulSlotCount);
    if(rv != CKR_OK)
      {
	printf("could not get slot count: %d",rv);
	exit(1);
      }
    printf("%d slots in total\n\n",ulSlotCount);
    
    pSlotList = malloc(sizeof(CK_SLOT_ID)*ulSlotCount);
    if(pSlotList == NULL)
      {
	printf("could not allocate slot list: %d",CKR_HOST_MEMORY);
	exit(1);
      }
    
    rv = (pFunctionList->C_GetSlotList)(FALSE,pSlotList,&ulSlotCount);
    if(rv != CKR_OK)
      {
	printf("could not get slot List: %d",rv);
	exit(1);
      }
    
    for(i=0;i<ulSlotCount;i++)
      {
	CK_SLOT_INFO SlotInfo;
	CK_TOKEN_INFO TokenInfo;
	CK_SESSION_HANDLE sess;
	
	rv= (pFunctionList->C_GetSlotInfo)(pSlotList[i],&SlotInfo);
        if(rv != CKR_OK)
	  {
	    printf("could not get slot info for '%d': %d",pSlotList[i],rv);
	    exit(1);
	  }
	/* print some info */
	printf("#%d: Slot: %d (%.64s),\n",
	       i,pSlotList[i],
	       SlotInfo.slotDescription);
	
	rv= display_token_info(pFunctionList,pSlotList[i]);
	if(rv == CKR_TOKEN_NOT_PRESENT)
	  {
	    printf("\tNo token present\n");
	  }
        else if(rv != CKR_OK)
	  {
	    printf("could not get token info for '%d': %d",pSlotList[i],rv);
	    exit(1);
	  }
	else
	  {
#if 0
	    CK_CHAR outbuf[2048];
	    CK_ULONG buff_len = 2046;

	    CK_MECHANISM mech = {CKM_RSA_PKCS, NULL_PTR, 0x00000000};
#endif

	    
	    /* open a session to test the loading of the objects */
	    rv = (pFunctionList->C_OpenSession)(pSlotList[i],CKF_SERIAL_SESSION,NULL,NULL,&sess);
	    if(rv != CKR_OK)
	      {
		printf("could not open session on slot %d: %d",pSlotList[i],rv);
		exit(1);
	      }
	    
	    /* build a little statistic over the objects on the token */
	    read_statistic(sess,pFunctionList,pSlotList[i]);

	    /* and clean up session */
	    rv = (pFunctionList->C_CloseSession)(sess);

	  }
      }
    free(pSlotList);
  }

  (pFunctionList->C_Finalize)(NULL);

  {
    char buf[3]={1};
    printf("weiter mit return");
    _cgets(buf);
  }
}
/* }}} */

/*
 * Local variables:
 * folded-file: t
 * end:
 */
