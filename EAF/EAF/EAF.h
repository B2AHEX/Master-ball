#pragma once
#include "windows.h"
#include <string>
#include <vector>
#include <map>
#include <iostream>

#define		MZ_Flag		"_MZ"   
#define		EAT_Flag	"_EAT"
#define     PAGE_SIZE	4096

namespace memprotection {

	extern PCHAR EAT_ModuleList[];

	class EAF
	{
	private:
		std::map<uintptr_t,std::string> protmap;
		std::string status;

	public:
		EAF();
		explicit EAF(std::string i) : status(i){ Start(); };
		~EAF();

		EAF(const EAF&);
		void operator=(const EAF&);

	private:
		unsigned int Start();
		unsigned int Stop();

	public:
		unsigned int CheckMalice(PEXCEPTION_POINTERS ExceptionInfo,uintptr_t upt_excep_addr);
		unsigned int SearchMapAddress(uintptr_t upt_excep_addr) const;
		unsigned int SetGuardFlag();

	private:
		unsigned int InsertMap(std::string dllname);
		uintptr_t    GetEAT(uintptr_t base);
	};

}