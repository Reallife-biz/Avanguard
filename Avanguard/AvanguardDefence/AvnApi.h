#pragma once

#include <Windows.h>

typedef VOID	(WINAPI *_AvnLock)();
typedef VOID	(WINAPI *_AvnUnlock)();
typedef VOID	(WINAPI *_AvnRehashModule)(HMODULE hModule);
typedef BOOL	(WINAPI *_AvnIsModuleValid)(HMODULE hModule);
typedef BOOL	(WINAPI *_AvnIsFileProtected)(LPCWSTR FilePath);
typedef BOOL	(WINAPI *_AvnIsFileSigned)(LPCWSTR FilePath, BOOL CheckRevocation);
typedef BOOL	(WINAPI *_AvnVerifyEmbeddedSignature)(LPCWSTR FilePath);
typedef BOOL	(WINAPI *_AvnIsAddressAllowed)(PVOID Address, BOOL IncludeJitMemory);

typedef struct _AVN_API {
	_AvnLock AvnLock;
	_AvnUnlock AvnUnlock;
	_AvnRehashModule AvnRehashModule;
	_AvnIsModuleValid AvnIsModuleValid;
	_AvnIsFileProtected AvnIsFileProtected;
	_AvnIsFileSigned AvnIsFileSigned;
	_AvnVerifyEmbeddedSignature AvnVerifyEmbeddedSignature;
	_AvnIsAddressAllowed AvnIsAddressAllowed;
} AVN_API, *PAVN_API;