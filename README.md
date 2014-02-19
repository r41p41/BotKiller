BotKiller
=========

find and kill malwares from memory
---------

finds and kills all forms of injected code system wide in x86 processes & WOW64 processes.<br>
-	runPE created Programs and its threads<br>
-	injected Shellcode via ZwWriteVirtualMemory/gapz_injection/NtMapViewOfSection_injection<br>
Removes malicious as well as non existential entries from registry<br>
For elevated processes code needs elevation via UAC<br>
can be hacked a bit to make it work with 64bit malwares =)<br>
-	changing GetThreadStartAddress is necessary<br>
**To do:<br>**
Add inline Hooks Remover<br>
