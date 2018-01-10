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

void MemoryStorage::AddRegion(PVOID Address, SIZE_T Size) {
	REGION_DESCRIPTOR Descriptor;
	Descriptor.Begin = (PVOID)AlignDown((SIZE_T)Address, PAGE_SIZE);
	Descriptor.End = (PVOID)(AlignUp((SIZE_T)Address + Size, PAGE_SIZE) - 1);
	MemoryMap.emplace_back(Descriptor);
}

void MemoryStorage::RemoveRegion(PVOID Address, SIZE_T Size) {
	PVOID Begin = (PVOID)AlignDown((SIZE_T)Address, PAGE_SIZE);
	PVOID End = (PVOID)(AlignUp((SIZE_T)Address + Size, PAGE_SIZE) - 1);
	std::remove_if(MemoryMap.begin(), MemoryMap.end(), [&](const REGION_DESCRIPTOR& Entry) -> bool {
		return (Entry.Begin >= Begin) && (Entry.End <= End);
	});
}

void MemoryStorage::ReloadMemoryRegions() {
	Lock();
	MemoryMap.clear();
	EnumerateMemoryRegions(GetCurrentProcess(), [this](const PMEMORY_BASIC_INFORMATION Info) -> bool {
		if (Info->Protect & EXECUTABLE_MEMORY) 
			AddRegion(Info->BaseAddress, Info->RegionSize);
		return true;
	});
	Unlock();
}

void MemoryStorage::ProcessAllocation(PVOID Base, SIZE_T Size) {
	Lock();
	AddRegion(Base, Size);
	Unlock();
}

template <typename ContainerT, typename PredicateT >
void erase_if(ContainerT& items, const PredicateT& predicate) {
	for (auto& it = items.begin(); it != items.end(); ) {
		if (predicate(*it)) 
			it = items.erase(it);
		else 
			it++;
	}
};

void MemoryStorage::ProcessFreeing(PVOID Base, SIZE_T Size) {
	Lock();
	RemoveRegion(Base, Size);
	Unlock();
}

bool MemoryStorage::IsMemoryInMap(PVOID Address) {
	Lock();
	bool IsInMap;
	for (auto& it = MemoryMap.begin(); it != MemoryMap.end(); it++) {
		IsInMap = (it->Begin <= Address) && (it->End >= Address);
		if (IsInMap) break;
	}
	Unlock();
	return IsInMap;
}