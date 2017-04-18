#pragma once
#include "EAF.h"
#include "ExceptionHandler.h"

namespace memprotection {

	class Guard
	{
	public:
		Guard(void);
		~Guard(void);

		Guard(const Guard&);
		void operator=(const Guard&);

	public:
		static unsigned int Start();
		static unsigned int Stop();

	public:
		static EAF*         pEAF_Guard;
		static std::mutex*  pEAF_Mtx;
		static unsigned int status;

	private:
		static uintptr_t uptVEH;

	};

}
