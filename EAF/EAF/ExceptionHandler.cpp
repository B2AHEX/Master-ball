#include "ExceptionHandler.h"

#pragma comment(lib,"libudis86.lib")

namespace memprotection {

	namespace ExceptionHandler {

		static std::list<uintptr_t>* pHardlist = nullptr;

		LONG CALLBACK VectoredHandler(
			_In_ PEXCEPTION_POINTERS ExceptionInfo
			)
		{
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
			{
				uintptr_t uptTagaddr = static_cast<uintptr_t>(ExceptionInfo->ExceptionRecord->ExceptionInformation[1]); 
				uintptr_t uptSrcaddr = reinterpret_cast<uintptr_t>(ExceptionInfo->ExceptionRecord->ExceptionAddress);  
				uintptr_t tagbp	= NULL;
				std::string SrcModuleName;
				
				if (GetModuleNameFromAddress(uptSrcaddr,SrcModuleName))
				{
					if (!SrcModuleName.compare(ExitMessage))
					{
						return EXCEPTION_CONTINUE_EXECUTION;
					}		
				}		

				if (!memprotection::Guard::pEAF_Guard || !memprotection::Guard::pEAF_Mtx)
				{
					return EXCEPTION_CONTINUE_EXECUTION;
				}

				memprotection::Guard::pEAF_Mtx->lock();

				if (memprotection::Guard::pEAF_Guard->SearchMapAddress(uptTagaddr))
				{
					if (memprotection::Guard::pEAF_Guard->CheckMalice(ExceptionInfo,uptSrcaddr))
					{
					/** Detect malicious access **/
						memprotection::Guard::status = TRUE;
					}
					if (!memprotection::Guard::status)
					{
						uintptr_t tagbp = uptSrcaddr + GetNextOrderLength(uptSrcaddr);

						if (!pHardlist)
							pHardlist = new std::list<uintptr_t>;

						pHardlist->push_back(tagbp);
						ExceptionInfo->ContextRecord->EFlags |= 0x100;
					}
									
					memprotection::Guard::pEAF_Mtx->unlock();
					return EXCEPTION_CONTINUE_EXECUTION;
				}

				//not we set
				memprotection::Guard::pEAF_Mtx->unlock();
			}
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
			{
				uintptr_t uptBPaddr = reinterpret_cast<uintptr_t>(ExceptionInfo->ExceptionRecord->ExceptionAddress);

				memprotection::Guard::pEAF_Mtx->lock();
				if (!pHardlist)
				{
					//not we set
					memprotection::Guard::pEAF_Mtx->unlock();
					return EXCEPTION_CONTINUE_SEARCH;
				}

				for (auto iter = pHardlist->begin(); iter != pHardlist->end();iter++)
				{
					if (*iter == uptBPaddr)
					{
						/** Reset MemoryGuaed **/
						if (memprotection::Guard::pEAF_Guard && !memprotection::Guard::status)
						{
							memprotection::Guard::pEAF_Guard->SetGuardFlag();
						}

						pHardlist->erase(iter++);
						memprotection::Guard::pEAF_Mtx->unlock();
						return EXCEPTION_CONTINUE_EXECUTION;

					}
				}
				
				//not we set
				memprotection::Guard::pEAF_Mtx->unlock();
			}

			return EXCEPTION_CONTINUE_SEARCH;
		}

		unsigned int GetNextOrderLength(uintptr_t uptCurAddr)
		{
			ud_t ud_obj;
			unsigned int len;
			ud_init(&ud_obj);

			ud_set_mode(&ud_obj, X86_model);
			ud_set_syntax(&ud_obj, UD_SYN_INTEL);
			ud_set_pc(&ud_obj, uptCurAddr);
			ud_set_input_buffer(&ud_obj, reinterpret_cast<uint8_t*>(uptCurAddr), X64_model * MAX_ORDER_LENGTH);

			len = ud_disassemble(&ud_obj);

			return len;
		}

		unsigned int GetModuleNameFromAddress(uintptr_t uptAddr, std::string &strModuleName)
		{
			HMODULE hmodule = NULL;
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCSTR>(uptAddr), &hmodule);

			if (!hmodule)
			{
				return FALSE;
			}

			PSTR pModuleName = new CHAR[MAX_PATH];
			ZeroMemory(pModuleName, MAX_PATH * sizeof(CHAR));

			GetModuleFileNameA(hmodule, pModuleName, MAX_PATH * sizeof(TCHAR));
			strModuleName = pModuleName;

			std::size_t ss = strModuleName.rfind('\\');
			if (ss != std::string::npos)
			{
				strModuleName = &strModuleName.c_str()[++ss];
			}

			return strModuleName.length();
		}

	}
}
