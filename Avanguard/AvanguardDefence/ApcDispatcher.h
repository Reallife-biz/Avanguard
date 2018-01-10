#pragma once

#include <winternl.h>
#include "hModules.h"
#include "..\\HoShiMin's API\\HookHelper.h"

/*
	ApcProc - APC-процедура
	Continue - адрес возврата на продолжение
*/
typedef BOOL (NTAPI *_ApcCallback)(PVOID ApcProc, PVOID Continue);

class ApcDispatcher final {
private:
	static BOOL Initialized;
public:
	static VOID SetupApcCallback(_ApcCallback Callback);
	static BOOL EnableApcFilter();
	static VOID DisableApcFilter();
};