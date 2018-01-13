#pragma once

#include <Windows.h>
#include <string>
#include <functional>

#include "PebTeb.h"

HMODULE GetModuleBase(PVOID Pointer);
std::wstring GetModuleName(HMODULE hModule);
std::wstring GetModuleName(PVOID Address);

typedef std::function<void(NTDEFINES::PLDR_MODULE Module)> EnumerateModulesCallback;
void EnumerateModules(EnumerateModulesCallback Callback);