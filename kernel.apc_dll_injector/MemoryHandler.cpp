#include "Definitions.h"
#include "MemoryHandler.h"

void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag) 
{
	return ExAllocatePoolWithTag(pool, size, tag);
}

void __cdecl operator delete(void* p, unsigned int dummy) 
{
	//for some reason it doesn't link unless the signature is (void* p, unsigned int dumy)
	UNREFERENCED_PARAMETER(dummy);
	ExFreePool(p);
}
