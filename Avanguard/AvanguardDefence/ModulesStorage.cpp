#include "stdafx.h"
#include "ModulesStorage.h"

#include <functional>
#include <apiset.h>

ModulesStorage::ModulesStorage(BOOL CollectModulesInfo) {
	InitializeCriticalSectionAndSpinCount(&CriticalSection, 0xC0000000);
	if (CollectModulesInfo) FillModulesInfo();
}

ModulesStorage::~ModulesStorage() {
	LoadedModules.clear();
}

HMODULE ModulesStorage::GetModuleBase(PVOID Pointer) {
	HMODULE hModule;
	BOOL Status = GetModuleHandleEx(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)Pointer,
		&hModule
	);
	return Status ? hModule : NULL;
}

std::wstring ModulesStorage::GetModuleName(HMODULE hModule) {
	if (hModule == NULL) return std::wstring();
	WCHAR Buffer[32768];
	DWORD Length = GetModuleFileName(hModule, Buffer, sizeof(Buffer));
	if (Length == 0) return std::wstring();
	return Buffer;
}

void ModulesStorage::AnalyzeExecutableSections(const PEAnalyzer& pe, MODULE_INFO& ModuleInfo) {
	const SECTIONS_SET& Sections = pe.GetSectionsInfo();
	ModuleInfo.ExecutableSections.clear();
	for (const auto& Section : Sections) {
		DWORD SecType = Section.Characteristics;
		if (((SecType & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE) ||
			((SecType & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)) 
		{
			EXECUTABLE_SECTION_INFO SectionInfo;
			SectionInfo.BaseAddress = (PVOID)((SIZE_T)(pe.GetLocalBase()) + Section.OffsetInMemory);
			SectionInfo.Size = Section.SizeInMemory;
			ModuleInfo.ExecutableSections.push_back(SectionInfo);
		}
	}
	ModuleInfo.Checksum = CalculateChecksum(ModuleInfo.ExecutableSections);
}


std::wstring ModulesStorage::GetNormalizedName(const std::wstring& Path) {
	std::wstring Name = LowerCase(ExtractFileName(Path));
	if (EndsWith(Name, DllPostfix) || EndsWith(Name, ExePostfix)) return Name;
	return Name += DllPostfix;
}

void ModulesStorage::EnumerateModules(EnumerateModulesCallback Callback) {
	if (Callback == NULL) return;
	
	NTDEFINES::PPEB Peb = GetPEB();
	NTDEFINES::PPEB_LDR_DATA LdrData = (NTDEFINES::PPEB_LDR_DATA)Peb->Ldr;

	NTDEFINES::PLDR_MODULE ListEntry = (NTDEFINES::PLDR_MODULE)LdrData->InLoadOrderModuleList.Flink;
	while (ListEntry && ListEntry->BaseAddress) {
		Callback(ListEntry);
		ListEntry = (NTDEFINES::PLDR_MODULE)ListEntry->InLoadOrderModuleList.Flink;
	}
}

void ModulesStorage::FillModulesInfo() {
	LoadedModules.clear();

	Lock();
	EnumerateModules([this](NTDEFINES::PLDR_MODULE Module) -> void {
		std::wstring ModuleName = GetNormalizedName(std::wstring(Module->BaseDllName.Buffer));

		PEAnalyzer pe((HMODULE)Module->BaseAddress, FALSE);
		MODULE_INFO ModuleInfo;
		ModuleInfo.BaseAddress = Module->BaseAddress;
		ModuleInfo.Name = ModuleName;
		AnalyzeExecutableSections(pe, ModuleInfo);
		LoadedModules.emplace((HMODULE)Module->BaseAddress, ModuleInfo);
	});
	Unlock();
}

UINT64 ModulesStorage::CalculateChecksum(const EXEC_SECTIONS_SET& Sections) {
	UINT64 Checksum = 0;
	for (const auto& Section : Sections) 
		Checksum ^= t1ha(Section.BaseAddress, Section.Size, 0x1EE7C0DEC0FFEE);
	return Checksum;
}

BOOL ModulesStorage::IsCodeSectionsValid(HMODULE hModule) {
	Lock();
	BOOL IsModuleValid = FALSE;
	auto& Module = LoadedModules.find(hModule);
	if (Module == LoadedModules.end()) goto Exit;
	UINT64 Checksum = CalculateChecksum(Module->second.ExecutableSections);
	IsModuleValid = Module->second.Checksum == Checksum;
Exit:
	Unlock();
	return IsModuleValid;
}

void ModulesStorage::RecalcModuleHash(HMODULE hModule) {
	Lock();
	auto& Module = LoadedModules.find(hModule);
	if (Module == LoadedModules.end()) goto Exit;
	Module->second.Checksum = CalculateChecksum(Module->second.ExecutableSections);
Exit:
	Unlock();
}

void ModulesStorage::RecalcModulesHashes() {
	Lock();
	for (auto& Entry : LoadedModules) {
		Entry.second.Checksum = CalculateChecksum(Entry.second.ExecutableSections);
	}
	Unlock();
}

void ModulesStorage::FindChangedModules(OnChangedModuleCallback Callback) {
	if (!Callback) return;
	Lock();
	for (const auto& Entry : LoadedModules) {
		if (Entry.second.Checksum != CalculateChecksum(Entry.second.ExecutableSections)) {
			if (!Callback(Entry.second)) goto Exit;
		}
	}
Exit:
	Unlock();
}

BOOL ModulesStorage::IsModuleInStorage(HMODULE hModule) {
	Lock();
	BOOL IsInStorage = LoadedModules.find(hModule) != LoadedModules.end();
	Unlock();
	return IsInStorage;
}

void ModulesStorage::AddModule(HMODULE hModule) {
	if (hModule == NULL) return;
	std::wstring Name = GetNormalizedName(GetModuleName(hModule));
	
	Lock();
	PEAnalyzer pe(hModule, FALSE);
	MODULE_INFO ModuleInfo;
	ModuleInfo.BaseAddress = (PVOID)hModule;
	ModuleInfo.Name = Name;
	AnalyzeExecutableSections(pe, ModuleInfo);
	LoadedModules.emplace(hModule, ModuleInfo);
	Unlock();
}

void ModulesStorage::RemoveModule(HMODULE hModule) {
	Lock();
	LoadedModules.erase(hModule);
	Unlock();
}

void ModulesStorage::Lock() {
	EnterCriticalSection(&CriticalSection);
}

void ModulesStorage::Unlock() {
	LeaveCriticalSection(&CriticalSection);
}