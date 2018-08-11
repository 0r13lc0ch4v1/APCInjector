#pragma once

void* __cdecl operator new(size_t size, POOL_TYPE pool, ULONG tag = 0);

void __cdecl operator delete(void*, unsigned int);
