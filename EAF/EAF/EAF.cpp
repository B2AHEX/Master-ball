#include "EAF.h"

namespace memprotection {

	PCHAR EAT_ModuleList[] = {
		"kernelbase.dll",
		"ntdll.dll",
		"kernel32.dll",
	};

	EAF::EAF()
	{	
		Start();
	}
	
	EAF::~EAF()
	{
		Stop();
	}

	unsigned int EAF::Start()
	{
		for (auto iter : memprotection::EAT_ModuleList)
		{
			InsertMap(iter);
		}

		SetGuardFlag();

		return static_cast<unsigned int>(protmap.size());
	}

	unsigned int EAF::Stop()
	{
		return true;
	}

	unsigned int EAF::SetGuardFlag()
	{
		for (auto iter : protmap)
		{
			uintptr_t tagAddr = iter.first;

			MEMORY_BASIC_INFORMATION mbi;
			ZeroMemory(&mbi, sizeof(mbi));
			VirtualQuery(reinterpret_cast<LPCVOID>(tagAddr), &mbi, sizeof(MEMORY_BASIC_INFORMATION));

			if (mbi.State == MEM_COMMIT)
			{
				if (!(mbi.Protect & PAGE_GUARD))
				{
					DWORD dwOldProt = NULL;
					::VirtualProtect(reinterpret_cast<LPVOID>(tagAddr), PAGE_SIZE, mbi.Protect|PAGE_GUARD, &dwOldProt);
				}
			}
		}
		
		return static_cast<unsigned int>(protmap.size());
	}

	unsigned int EAF::SearchMapAddress(uintptr_t upt_excep_addr) const
	{
		for (auto iter : protmap)
		{
			if ((upt_excep_addr & 0xFFFFF000) == iter.first)
			{
				return TRUE;
			}
		}
		return FALSE;
	}

	unsigned int EAF::InsertMap(std::string dllname)
	{
		if (dllname.length())
		{
			uintptr_t uptModule = 
				reinterpret_cast<uintptr_t>(::GetModuleHandleA(dllname.c_str()));

			if (uptModule)
			{
				std::string strMZ = dllname + MZ_Flag;
				protmap.insert(std::pair<uintptr_t, std::string>(uptModule, strMZ));

				std::string strEAT = dllname + EAT_Flag;
				protmap.insert(std::pair<uintptr_t, std::string>(GetEAT(uptModule), strEAT));
				return static_cast<unsigned int>(uptModule);
			}

		}

		return FALSE;
	}

	uintptr_t EAF::GetEAT(uintptr_t base)
	{
		IMAGE_DOS_HEADER * pDosHeader    = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		IMAGE_NT_HEADERS * pNtHeader     = reinterpret_cast<PIMAGE_NT_HEADERS>(pDosHeader->e_lfanew + base);
		IMAGE_EXPORT_DIRECTORY * pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>
			(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + base);
		
		return  static_cast<uintptr_t>(pExport->Name + base);
	}

	unsigned int EAF::CheckMalice(PEXCEPTION_POINTERS ExceptionInfo,uintptr_t upt_excep_addr)
	{
		if (ExceptionInfo && upt_excep_addr)
		{
			uintptr_t StackBase  = __readfsdword(0x4);
			uintptr_t StackLimit = __readfsdword(0x8);
			
			uintptr_t uptESP = ExceptionInfo->ContextRecord->Esp;
			uintptr_t uptEBP = ExceptionInfo->ContextRecord->Ebp;

			if (uptEBP > StackBase || uptEBP < StackLimit)
			{
				return TRUE;
			}

			if (uptESP > StackBase || uptESP < StackLimit)
			{
				return TRUE;
			}



		}
		return FALSE;
	}
}