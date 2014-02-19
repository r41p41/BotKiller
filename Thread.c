/*
generic way to detect Actual Thread OEP iterate all seh handlers till we reach 0xffffffff
note the address at which -1 or last handler's address is located and label this temp.
add 0x30 to  temp, and simultaneously add 0x18 to temp.
they both will be equal to each other and point to start address in normal circumstances under windows xp and +.
in some flavours of windows xp 0x18 will point to OEP of thread but 0x30 will be out of bounds.
*/

#include<tlhelp32.h>
struct Thread_info
{
	DWORD Pid;
	DWORD Tid;
	DWORD OEP;
	DWORD ImageType;
	DWORD AllocationType;
	struct Thread_info *next;
};
struct Process_info
{
	DWORD pid;
	unsigned char name[100];
	struct Process_info *next;
};

DWORD GetThreadStartAddress(HANDLE hThread,HANDLE hProcess)
{
	typedef struct _THREAD_BASIC_INFORMATION
	{
		int ExitStatus;
		PVOID TebBaseAddress;
		DWORD a,b,c,d,e;				//unimportant
	}THREAD_BASIC_INFORMATION;

	THREAD_BASIC_INFORMATION tbi;
	FARPROC qti;
	DWORD ntdll,temp=0,temp2=0,temp3=0,pd=0;
	ntdll = (DWORD) GetModuleHandle("ntdll");
	if(ntdll)
	{
		qti=GetProcAddress(ntdll,"ZwQueryInformationThread");
		if(qti)
		{
			qti(hThread,0,&tbi,sizeof(THREAD_BASIC_INFORMATION),NULL);
			if(tbi.TebBaseAddress)
			{
				SuspendThread(hThread);
				
				if(ReadProcessMemory(hProcess,tbi.TebBaseAddress,&temp2,4,&pd)) 	//temp2 gets fs:[0x00] or current seh handler)
				{
					while(temp!=0xffffffff)             							//iterate all seh handlers till we reach last
					{
						if(ReadProcessMemory(hProcess,temp2,&temp,4,&pd)==0)
						break;
                    	if(temp!=0xffffffff)temp2=temp;
                    }
				}
				ResumeThread(hThread);
			}
		}
	}
	temp=0;
	temp3=0;
	ReadProcessMemory(hProcess,temp2+0x18,&temp,4,&pd);
	ReadProcessMemory(hProcess,temp2+0x30,&temp3,4,&pd);
	/*  experimental
	if(temp == temp3) 	
	return temp;		
	else
	return temp;
	*/
	return temp;
}
struct Thread_info * init(HANDLE heap)
{
	struct Thread_info *tinfo;
	tinfo = HeapAlloc(heap,HEAP_ZERO_MEMORY,sizeof(struct Thread_info));
	if(tinfo == NULL)
	{
		MessageBox(0,"Heap Cannot be allocated","Error",0);
		return 0;
	}
	return tinfo;
}
struct Thread_info *  ListThreads(HANDLE heap)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE,hProcess,hThread; 
	THREADENTRY32 te32; 
	MEMORY_BASIC_INFORMATION mbi;
	struct Thread_info *tinfo,*Start;
	
	hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
		return( FALSE ); 
	te32.dwSize = sizeof(THREADENTRY32 );
	if( !Thread32First( hThreadSnap, &te32 ) ) 
	{
		CloseHandle( hThreadSnap );     // Must clean up the snapshot object!
		return( FALSE );
	}	
	Start = init(heap);
	if(Start == 0)
	return 0;
	tinfo = Start;
	
	do
	{
		if(te32.th32ThreadID == GetCurrentThreadId())
		continue;
		
		
		tinfo->Tid = te32.th32ThreadID;
		tinfo->Pid = te32.th32OwnerProcessID;
		
		hThread = OpenThread(THREAD_ALL_ACCESS,0,tinfo->Tid);
		hProcess = OpenProcess(PROCESS_ALL_ACCESS,0,tinfo->Pid);
		
		if(hThread && hProcess)
		{
			tinfo->OEP = GetThreadStartAddress(hThread,hProcess);
			if(tinfo->OEP)
			{
				VirtualQueryEx(hProcess,tinfo->OEP,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
				tinfo->ImageType = mbi.Type;
				tinfo->AllocationType = mbi.AllocationProtect;
			}
		}
		
		CloseHandle(hProcess);
		CloseHandle(hThread);
		
		
		tinfo->next = init(heap);
		if(tinfo->next == NULL)
		return 0;
		tinfo = tinfo->next;
	} while( Thread32Next(hThreadSnap, &te32 ) );
	CloseHandle( hThreadSnap );
	tinfo->Pid =-1;
	tinfo->Tid =-1;
	return Start;
}
