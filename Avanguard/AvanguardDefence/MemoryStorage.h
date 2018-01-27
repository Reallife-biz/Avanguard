#pragma once

#include <algorithm>
#include <unordered_set>

#include "ProcessAPI.h"

#define PAGE_SIZE 4096
#define EXECUTABLE_MEMORY (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

class MemoryStorage {
private:
	CRITICAL_SECTION CriticalSection;
	std::unordered_set<PVOID> MemoryMap;
	void AddRegion(PVOID Address);
	void RemoveRegion(PVOID Address);
public:
	MemoryStorage();
	~MemoryStorage();

	void Lock();
	void Unlock();

	void ReloadMemoryRegions();

	void ProcessAllocation(PVOID Base);
	void ProcessFreeing(PVOID Base);
	bool IsMemoryInMap(PVOID Address);
};