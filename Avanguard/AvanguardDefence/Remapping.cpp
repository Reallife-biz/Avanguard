#include "stdafx.h"
#include <Windows.h>

#include "Remapping.h"
#include "hModules.h"
#include "PEAnalyzer.h"

#include <vector>

typedef struct _SEC_INFO {
	PVOID OriginalAddress;
	PVOID ShadowAddress;
	SIZE_T Size;
	BOOL Executable;
} SEC_INFO, *PSEC_INFO;

typedef BOOL(WINAPI *_UnmapViewOfFile)(PVOID Address);
typedef BOOL(WINAPI *_MapViewOfFileEx)(HANDLE hMapping, DWORD Access, DWORD OffsetHigh, DWORD OffsetLow, SIZE_T BytesToMap, PVOID TargetAddress);

typedef struct _REMAP_PARAMETERS {
	HANDLE hMapping;
	HMODULE hModule;
	PVOID Shadow;
	_UnmapViewOfFile UnmapViewOfFile;
	_MapViewOfFileEx MapViewOfFileEx;
	PSEC_INFO SecInfo;
	SIZE_T SectionsCount;
} REMAP_PARAMETERS, *PREMAP_PARAMETERS;

static VOID RemapSections(PREMAP_PARAMETERS RemapParameters) {
	BOOL Status = RemapParameters->UnmapViewOfFile(RemapParameters->hModule);
	if (!Status) return;

	// Map of sections:
	for (SIZE_T i = 0; i < RemapParameters->SectionsCount; i++) {
		PSEC_INFO Section = RemapParameters->SecInfo + i;
		RemapParameters->MapViewOfFileEx(
			RemapParameters->hMapping,
			Section->Executable ? FILE_MAP_READ | FILE_MAP_EXECUTE | SECTION_MAP_EXECUTE_EXPLICIT : FILE_MAP_ALL_ACCESS,
			0, 
			(DWORD)((SIZE_T)Section->OriginalAddress - (SIZE_T)RemapParameters->hModule),
			Section->Size,
			Section->OriginalAddress
		);
	}

	// Map of PE-header:
	RemapParameters->MapViewOfFileEx(RemapParameters->hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, USN_PAGE_SIZE, RemapParameters->hModule);
}

BOOL RemapModule(HMODULE hModule, BOOL UnmapShadowMemory) {

	PEAnalyzer pe(hModule, FALSE);
	DWORD ImageSize = pe.GetOptionalHeader()->SizeOfImage;

	// Создаём объект отображения:
	HANDLE hMapping = CreateFileMapping(NULL, NULL, PAGE_EXECUTE_READWRITE, 0, ImageSize, NULL);
	if (hMapping == NULL) return FALSE;

	// Мапим отображение для теневой памяти:
	PVOID Shadow = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS | SECTION_MAP_EXECUTE_EXPLICIT, 0, 0, ImageSize);
	if (Shadow == NULL) {
		CloseHandle(hMapping);
		return FALSE;
	}

	std::vector<SEC_INFO> SectionsInfo;
	const auto& Sections = pe.GetSectionsInfo();
	for (const auto& Section : Sections) {
		DWORD SecType = Section.Characteristics;
		SEC_INFO SecInfo = { 0 };
		SecInfo.OriginalAddress = (PVOID)((PBYTE)hModule + Section.OffsetInMemory);
		SecInfo.ShadowAddress = (PVOID)((PBYTE)Shadow + Section.OffsetInMemory);
		SecInfo.Size = Section.SizeInMemory;
		SecInfo.Executable = (SecType & IMAGE_SCN_CNT_CODE) || (SecType & IMAGE_SCN_MEM_EXECUTE);
		CopyMemory(SecInfo.ShadowAddress, SecInfo.OriginalAddress, SecInfo.Size);
		SectionsInfo.emplace_back(SecInfo);
	}

	REMAP_PARAMETERS RemapParameters = { 0 };
	RemapParameters.hMapping = hMapping;
	RemapParameters.hModule = hModule;
	RemapParameters.Shadow = Shadow;
	RemapParameters.UnmapViewOfFile = (_UnmapViewOfFile)GetProcAddress(hModules::hKernel32(), "UnmapViewOfFile");
	RemapParameters.MapViewOfFileEx = (_MapViewOfFileEx)GetProcAddress(hModules::hKernel32(), "MapViewOfFileEx");
	RemapParameters.SecInfo = &(SectionsInfo[0]);
	RemapParameters.SectionsCount = SectionsInfo.size();

	typedef PVOID(WINAPI *_RemapSections)(PREMAP_PARAMETERS RemapParameters);
	_RemapSections RemapSectionsShadow = (_RemapSections)((PBYTE)Shadow + ((PBYTE)&RemapSections - (PBYTE)hModule));
	RemapSectionsShadow(&RemapParameters);

	// Размапливаем теневую память:
	if (UnmapShadowMemory) UnmapViewOfFile(Shadow);
	
	CloseHandle(hMapping);
	return TRUE;
}