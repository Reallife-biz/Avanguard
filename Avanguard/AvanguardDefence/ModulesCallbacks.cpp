#include "stdafx.h"
#include "ModulesCallbacks.h"

ModulesStorage ValidModulesStorage(TRUE);

static _OnWindowsHookLoad WinHookLoadCallback;
static _OnUnknownTraceLoad UnknownTraceLoadCallback;

NTSTATUS CALLBACK PreLoadModuleCallback(
	OUT PBOOL			SkipOriginalCall,
	IN PWCHAR			PathToFile,
	IN PULONG			Flags,
	IN PUNICODE_STRING	ModuleFileName,
	OUT PHANDLE			ModuleHandle
) {
#if defined WINDOWS_HOOKS_FILTER || defined STACKTRACE_CHECK
	__declspec(thread) static unsigned int LoadingCount = 0;

	if (LoadingCount == 0) {
#ifdef WINDOWS_HOOKS_FILTER
		LoadingCount++;
		if (WinHooks::IsCalledFromWinHook() && WinHookLoadCallback) 
			*SkipOriginalCall = !WinHookLoadCallback(ModuleFileName);
#endif

#ifdef STACKTRACE_CHECK
		const int TraceCount = 35;
		PVOID Ptrs[TraceCount];
		USHORT Captured = CaptureStackBackTrace(0, TraceCount, Ptrs, NULL);
		for (unsigned short i = 0; i < Captured; i++) {
			PVOID Address = Ptrs[i];
			HMODULE hModule = ModulesStorage::GetModuleBase(Address);
#ifdef MEMORY_FILTER
			BOOL IsAddressAllowed = hModule == NULL 
				? VMStorage.IsMemoryInMap(Address) 
				: ValidModulesStorage.IsModuleInStorage(hModule);
#else
			BOOL IsAddressAllowed = hModule != NULL 
				? ValidModulesStorage.IsModuleInStorage(hModule) 
				: FALSE;
#endif
			if (!IsAddressAllowed && *SkipOriginalCall && UnknownTraceLoadCallback) 
				*SkipOriginalCall = !UnknownTraceLoadCallback(Address, ModuleFileName);
		}
#endif

		LoadingCount--;
	}
#endif
	return STATUS_SUCCESS;
}

VOID CALLBACK DllNotificationRoutine(
	LDR_NOTIFICATION_REASON Reason,
	IN PLDR_DLL_NOTIFICATION_DATA NotificationData,
	IN PCONTEXT Context
) {
	switch (Reason) {
	case LdrModuleLoaded:
		ValidModulesStorage.AddModule((HMODULE)NotificationData->DllBase);
		break;

	case LdrModuleUnloaded:
		ValidModulesStorage.RemoveModule((HMODULE)NotificationData->DllBase);
		break;
	}
}

VOID SetupWindowsHooksFilter(_OnWindowsHookLoad Callback) {
	WinHookLoadCallback = Callback;
}

VOID SetupUnknownTraceLoadCallback(_OnUnknownTraceLoad Callback) {
	UnknownTraceLoadCallback = Callback;
}