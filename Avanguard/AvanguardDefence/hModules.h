#pragma once

#include <Windows.h>

class hModules final {
private:
	static BOOL Initialized;
	static HMODULE _hNtdll;
	static HMODULE _hKernelBase;
	static HMODULE _hKernel32;
	static HMODULE _hProcess;
public:
	static HMODULE _hCurrent; // Current module
	static inline HMODULE hNtdll();
	static inline HMODULE hKernelBase();
	static inline HMODULE hKernel32();
	static inline HMODULE hProcess();
	static inline HMODULE hCurrent();
};



#define GET_HMODULE(VarName, LibName) VarName ? VarName : VarName = GetModuleHandle(LibName)

inline HMODULE hModules::hNtdll() {
	return GET_HMODULE(_hNtdll, L"ntdll.dll");
}

inline HMODULE hModules::hKernelBase() {
	return GET_HMODULE(_hKernelBase, L"kernelbase.dll");
}

inline HMODULE hModules::hKernel32() {
	return GET_HMODULE(_hKernel32, L"kernel32.dll");
}

inline HMODULE hModules::hProcess() {
	return GET_HMODULE(_hProcess, NULL);
}

inline HMODULE hModules::hCurrent() {
	return _hCurrent;
}

#undef GET_HMODULE