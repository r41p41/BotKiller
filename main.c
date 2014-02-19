/*
Compiled with Visual Studio 2012 under x86 build Release
finds and kills all forms of injected code system wide in x86 processes & WOW64 processes.
including runPE created Programs and its threads
for elevated processes code needs elevation via UAC


can be hacked a bit to make it work with 64bit malwares =)\
changing GetThreadStartAddress is necessary
*/
#include <windows.h>
#include "Debug.c"
#include "Reg.c"
#include "Low.c"
#include "Thread.c"

int WinMainCRTStartup()
{
	if(!DebugPriv(1))
	return 0;

	
	struct Thread_info *tinfo=NULL,*iterator;
	HANDLE hHeap,hThread;
	hHeap = HeapCreate(HEAP_NO_SERIALIZE,sizeof(struct Thread_info),0);
	
	tinfo=ListThreads(hHeap);
	
	if(tinfo == 0)
		goto end;
	iterator = tinfo;
	while((iterator->Pid != -1) && (iterator->Tid != -1))
	{
		if((iterator->OEP!=0 && iterator->AllocationType==PAGE_EXECUTE_READWRITE && iterator->ImageType!=MEM_IMAGE))
		{	
			/*
			printf("\nPid = %d",iterator->Pid);
			printf("\nTid = %d",iterator->Tid);
			printf("\nOEP = %x",iterator->OEP);
			printf("\nAllocType = %x\n",iterator->AllocationType);
			printf("heur.injected Shellcode\n\n");
			*/
			
			hThread = OpenThread(THREAD_ALL_ACCESS,0,iterator->Tid);
			TerminateThread(hThread,0);
		}
		if((iterator->OEP!=0  && iterator->ImageType!=MEM_IMAGE))
		{	
			/*
			printf("\nPid = %d",iterator->Pid);
			printf("\nTid = %d",iterator->Tid);
			printf("\nOEP = %x",iterator->OEP);
			printf("\nAllocType = %x\n",iterator->AllocationType);
			printf("heur.injected PE/runPE\n\n");
			*/
			
			hThread = OpenThread(THREAD_ALL_ACCESS,0,iterator->Tid);
			TerminateThread(hThread,0);
		}
	}
	
	end:
	HeapDestroy(hHeap);
	tinfo = NULL;
	clean_reg();
}
