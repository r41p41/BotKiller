BotKiller
=========

find and kill malwares from memory
finds and kills all forms of injected code system wide in x86 processes & WOW64 processes.
	->runPE created Programs and its threads
  ->injected Shellcode via ZwWriteVirtualMemory/gapz_injection/NtMapViewOfSection_injection
  
Removes malicious as well as non existential entries from registry
  
for elevated processes code needs elevation via UAC
can be hacked a bit to make it work with 64bit malwares =)
  ->changing GetThreadStartAddress is necessary
  
To do:
Add inline Hooks Remover
