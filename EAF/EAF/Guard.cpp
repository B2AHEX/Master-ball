#include "Guard.h"

namespace memprotection {

	EAF*		  Guard::pEAF_Guard = nullptr;
	std::mutex*   Guard::pEAF_Mtx   = nullptr;
	uintptr_t	  Guard::uptVEH     = NULL;
	unsigned int  Guard::status		= FALSE;

	Guard::Guard(void)
	{
	}


	Guard::~Guard(void)
	{

	}

	unsigned int Guard::Start()
	{	
		if (!uptVEH)
		{
			status = FALSE;
			uptVEH =  reinterpret_cast<uintptr_t>(AddVectoredExceptionHandler(NULL, 
				ExceptionHandler::VectoredHandler));

			pEAF_Mtx   = new std::mutex;
			pEAF_Mtx->lock();
			pEAF_Mtx->unlock();
			pEAF_Guard = new EAF;
		}

		return uptVEH;
	}

	unsigned int Guard::Stop()
	{	
		status = TRUE;
		return uptVEH;
	}


}