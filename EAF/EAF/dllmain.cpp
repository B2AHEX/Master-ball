#ifndef _DEBUG
#include "Guard.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		memprotection::Guard::Start();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		memprotection::Guard::Stop();
		break;
	}
	return TRUE;
}
#else

#include <iostream>
#include <windows.h>
#include "Guard.h"

BOOL APIENTRY main(_In_ int _Argc, 
	_In_reads_(_Argc) _Pre_z_ char ** _Argv,
	_In_z_ char ** _Env)
{
	std::cout << "DEBUG ON" << std::endl;
	unsigned long* a = (unsigned long*)GetModuleHandleA("kernelbase.dll");

	memprotection::Guard::Start();
	std::cout << std::hex << (*a) << std::endl;

	while (1)
	{
		if ((BYTE)*((BYTE*)a) == 'a')
			return 1;
		a++;
		Sleep(1000);
		std::cout << std::hex << a <<" "<< std::endl;
	}

	return true;
}

#endif // DEBUG

static_assert(sizeof(void *) == 4, "64-bit code generation is not supported.");


