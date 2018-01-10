#pragma once

#include <algorithm>
#include <vector>

#include "ProcessAPI.h"

#define PAGE_SIZE 4096
#define EXECUTABLE_MEMORY (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

typedef struct _REGION_DESCRIPTOR {
	PVOID Begin; // Start address
	PVOID End; // End address
} REGION_DESCRIPTOR, *PREGION_DESCRIPTOR;

class MemoryStorage {
private:
	CRITICAL_SECTION CriticalSection;
	std::vector<REGION_DESCRIPTOR> MemoryMap;
	void AddRegion(PVOID Address, SIZE_T Size);
	void RemoveRegion(PVOID Address, SIZE_T Size);
public:
	MemoryStorage();
	~MemoryStorage();

	void Lock();
	void Unlock();

	void ReloadMemoryRegions();

	void ProcessAllocation(PVOID Base, SIZE_T Size);
	void ProcessFreeing(PVOID Base, SIZE_T Size);
	bool IsMemoryInMap(PVOID Address);
};