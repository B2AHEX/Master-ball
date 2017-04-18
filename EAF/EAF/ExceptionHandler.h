#pragma once
#include <Windows.h>
#include <list>
#include <thread>
#include <mutex>
#include "eaf.h"
#include "Guard.h"
#include "../Udis86/udis86.h"

#define MAX_ORDER_LENGTH     16
#define X86_model			 32
#define X64_model	         64
#define ExitMessage	         "ntdll.dll"

namespace memprotection {

	namespace ExceptionHandler {

		LONG CALLBACK VectoredHandler(
			_In_ PEXCEPTION_POINTERS ExceptionInfo
			);

		unsigned int GetModuleNameFromAddress(uintptr_t uptAddr, std::string &strModuleName);
		unsigned int GetNextOrderLength(uintptr_t uptCurAddr);

	}
}
