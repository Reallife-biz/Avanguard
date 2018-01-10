#pragma once

#define ZYDIS_STATIC_DEFINE
#include "..\\Zydis\\Zydis\\Zydis.h"

#include <string>

typedef enum _CODE_ARCH {
	arch_x86,
	arch_x64,
	arch_native
} CODE_ARCH, *PCODE_ARCH;

typedef void (__stdcall *_OnDisassembleCallback) (
	void* Address, 
	char* Disassembly
);

std::string disassemble(
	_OnDisassembleCallback callback,
	void* code,
	void* base_address,
	int instructions_count,
	CODE_ARCH arch = arch_native
);