#include "stdafx.h"
#include "MemoryStorage.h"

size_t inline AlignDown(size_t Value, size_t Factor) {
	return Value & ~(Factor - 1);
}

size_t inline AlignUp(size_t Value, size_t Factor) {
	return AlignDown(Value - 1, Factor) + Factor;
}

MemoryStorage::MemoryStorage() {
	InitializeCriticalSectionAndSpinCount(&CriticalSection, 0xC0000000);
	ReloadMemoryRegions();
}

MemoryStorage::~MemoryStorage() {
	DeleteCriticalSection(&CriticalSection);
	MemoryMap.clear();
}

void MemoryStorage::Lock() {
	EnterCriticalSection(&CriticalSection);
}

void MemoryStorage::Unlock() {
	LeaveCriticalSection(&CriticalSection);
}

void MemoryStorage::AddRegion(PVOID Address) {
	MEMORY_BASIC_INFORMATION MemoryInfo;
	QueryVirtualMemory(Address, &MemoryInfo);
	MemoryMap.emplace(MemoryInfo.AllocationBase);
}

void MemoryStorage::RemoveRegion(PVOID Address) {
	MEMORY_BASIC_INFORMATION MemoryInfo;
	QueryVirtualMemory(Address, &MemoryInfo);
	if (MemoryMap.find(MemoryInfo.AllocationBase) != MemoryMap.end())
		MemoryMap.erase(MemoryInfo.AllocationBase);
}

void MemoryStorage::ReloadMemoryRegions() {
	Lock();
	MemoryMap.clear();
	EnumerateMemoryRegions(GetCurrentProcess(), [this](const PMEMORY_BASIC_INFORMATION Info) -> bool {
		if (Info->Protect & EXECUTABLE_MEMORY) 
			AddRegion(Info->BaseAddress);
		return true;
	});
	Unlock();
}

void MemoryStorage::ProcessAllocation(PVOID Base) {
	Lock();
	AddRegion(Base);
	Unlock();
}

void MemoryStorage::ProcessFreeing(PVOID Base) {
	Lock();
	RemoveRegion(Base);
	Unlock();
}

bool MemoryStorage::IsMemoryInMap(PVOID Address) {
	MEMORY_BASIC_INFORMATION MemoryInfo;
	QueryVirtualMemory(Address, &MemoryInfo);
	Lock();
	bool IsInMap = MemoryMap.find(MemoryInfo.AllocationBase) != MemoryMap.end();
	Unlock();
	return IsInMap;
}