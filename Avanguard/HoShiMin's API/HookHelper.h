#pragma once

#include <Windows.h>
#include "..\\MinHook\\MinHook.h"

typedef struct _HOOK_INFO {
	PVOID	TargetProc;
	PVOID	HookProc;
	PVOID*	OriginalProc;
} HOOK_INFO, *PHOOK_INFO;

VOID FORCEINLINE UnHookEmAll(const PHOOK_INFO HookInfoArray, ULONG EntriesCount) {
	for (unsigned int i = 0; i < EntriesCount; i++) {
		MH_DisableHook(HookInfoArray[i].TargetProc);
		MH_RemoveHook(HookInfoArray[i].TargetProc);
	}
}

static BOOL HookEmAll(const PHOOK_INFO HookInfoArray, ULONG EntriesCount) {
	MH_STATUS MhStatus;
	MhStatus = MH_Initialize();
	if (MhStatus != MH_OK && MhStatus != MH_ERROR_ALREADY_INITIALIZED) return FALSE;

	for (unsigned int i = 0; i < EntriesCount; i++) {
		MhStatus = MH_CreateHook(HookInfoArray[i].TargetProc, HookInfoArray[i].HookProc, HookInfoArray[i].OriginalProc);
		if (MhStatus != MH_OK) {
			UnHookEmAll(HookInfoArray, i);
			return FALSE;
		}
		MhStatus = MH_EnableHook(HookInfoArray[i].TargetProc);
		if (MhStatus != MH_OK) {
			MH_RemoveHook(HookInfoArray[i].TargetProc);
			UnHookEmAll(HookInfoArray, i);
			return FALSE;
		}
	}

	return TRUE;
}

#define INTERCEPTION_ENTRY(Address, FunctionName) { Address, (LPVOID)Hkd##FunctionName, (LPVOID*)&Orgnl##FunctionName }

#define INTERCEPT(Address, FunctionName) \
MH_CreateHook(Address, (LPVOID)Hkd##FunctionName, (LPVOID*)&Orgnl##FunctionName)

#define ENABLE_HOOK(Address) \
MH_EnableHook(Address)

#define INTERCEPTION(ReturnType, Convention, FunctionName, ...)		\
	typedef ReturnType (Convention *_##FunctionName) (__VA_ARGS__);	\
	static _##FunctionName Orgnl##FunctionName;						\
	static ReturnType Convention Hkd##FunctionName(__VA_ARGS__)

#define FILTRATION(ReturnType, Convention, FunctionName, ...)										\
	typedef ReturnType (Convention *_##FunctionName) (__VA_ARGS__);									\
	typedef ReturnType (Convention *_Pre##FunctionName) (OUT PBOOL SkipOriginalCall, __VA_ARGS__);	\
	typedef ReturnType (Convention *_Post##FunctionName) (IN ReturnType ReturnValue, __VA_ARGS__);	\
	static _##FunctionName Orgnl##FunctionName;														\
	static _Pre##FunctionName pPre##FunctionName = NULL;											\
	static _Post##FunctionName pPost##FunctionName = NULL;											\
	static ReturnType Convention Hkd##FunctionName(__VA_ARGS__)

#define FILTRATE(ReturnType, ResultVarName, FunctionName, ...)									\
	BOOL SkipOriginalCall = FALSE;																\
	ReturnType ResultVarName;																	\
	if (pPre##FunctionName) ResultVarName = pPre##FunctionName(&SkipOriginalCall, __VA_ARGS__);	\
	if (SkipOriginalCall) goto Post;															\
	ResultVarName = Orgnl##FunctionName(__VA_ARGS__);											\
Post:																							\
	if (pPost##FunctionName) ResultVarName = pPost##FunctionName(ResultVarName, __VA_ARGS__);	

#define FILTRATE_TO(ReturnType, ResultVarName, FunctionName, PreCallback, PostCallback, ...)	\
	BOOL SkipOriginalCall = FALSE;																\
	ReturnType ResultVarName;																	\
	if (PreCallback) ResultVarName = PreCallback(&SkipOriginalCall, __VA_ARGS__);				\
	if (SkipOriginalCall) goto Post;															\
	ResultVarName = Orgnl##FunctionName(__VA_ARGS__);											\
Post:																							\
	if (PostCallback) ResultVarName = PostCallback(ResultVarName, __VA_ARGS__);	


#define DEFINE_FILTERS(FunctionName, PreCallback, PostCallback) \
	pPre##FunctionName = PreCallback;							\
	pPost##FunctionName = PostCallback;