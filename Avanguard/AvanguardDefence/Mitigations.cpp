#include "stdafx.h"
#include "Mitigations.h"

BOOL Mitigations::Initialized = FALSE;

_SetThreadInformation Mitigations::__SetThreadInformation;
_SetProcessMitigationPolicy Mitigations::__SetProcessMitigationPolicy;

BOOL Mitigations::Initialize() {
#if (_WIN32_WINNT > _WIN32_WINNT_WINBLUE)
	if (!IsWindows8Point1OrGreater()) return FALSE;
	if (Initialized) return TRUE;
	__SetThreadInformation = (_SetThreadInformation)GetProcAddress(hModules::hKernel32(), "SetThreadInformation");
	__SetProcessMitigationPolicy = (_SetProcessMitigationPolicy)GetProcAddress(hModules::hKernel32(), "SetProcessMitigationPolicy");
	return Initialized = __SetThreadInformation && __SetProcessMitigationPolicy;
#else
	return FALSE;
#endif
}

BOOL Mitigations::SetProhibitDynamicCode(BOOL AllowThreadsOptOut) {
#if (_WIN32_WINNT > _WIN32_WINNT_WINBLUE)
	if (!Initialized && !Initialize()) return FALSE;

	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY Policy = { 0 };
	Policy.ProhibitDynamicCode = TRUE;
	Policy.AllowThreadOptOut = AllowThreadsOptOut;
	return __SetProcessMitigationPolicy(
		ProcessDynamicCodePolicy,
		&Policy,
		sizeof(Policy)
	);
#else
	return FALSE;
#endif
}

BOOL Mitigations::SetThreadAllowedDynamicCode() {
#if (_WIN32_WINNT > _WIN32_WINNT_WINBLUE)
	if (!Initialized && !Initialize()) return FALSE;

#define THREAD_DYNAMIC_CODE_ALLOW 1
	DWORD Policy = THREAD_DYNAMIC_CODE_ALLOW;
	BOOL Status = __SetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &Policy, sizeof(Policy));
	return Status;
#undef THREAD_DYNAMIC_CODE_ALLOW
#else
	return FALSE;
#endif
}