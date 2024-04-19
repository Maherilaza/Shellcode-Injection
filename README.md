# Shellcode Injection

A simple example of shellcode injection [[Win32 api]](https://learn.microsoft.com/en-us/windows/win32/api/)

* The Notepad process is created in suspended mode.
* Memory is allocated within the Notepad process for the shellcode.
* The shellcode is written into the allocated memory space.
* An asynchronous procedure call (APC) function is used to execute the shellcode.
* The Notepad process thread is then resumed to start executing the shellcode.

