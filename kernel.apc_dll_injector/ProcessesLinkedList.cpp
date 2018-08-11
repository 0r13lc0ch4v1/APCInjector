#include "Definitions.h"
#include "StringsUtils.h"
#include "MemoryHandler.h"

typedef struct _PROCESS_LIST_INFO
{
	WCHAR pszProcessName[MAX_PROCESS_NAME_LENGTH];
	ULONG ulProcessId;
	BOOLEAN bIsInjected;
	SINGLE_LIST_ENTRY ListEntry;
}	PROCESS_LIST_INFO, *PPROCESS_LIST_INFO;


struct SingleLinkedList {
	SingleLinkedList(
		_In_ POOL_TYPE pool = PagedPool,
		_In_ ULONG tag = 'DaOr')
	{
		DbgPrint("SingleLinkedList C'tor called");

		m_pProcessLinkedListHead = (PSINGLE_LIST_ENTRY)new(PagedPool, 'DaOr') SINGLE_LIST_ENTRY;
		NT_ASSERT(m_pProcessLinkedListHead);
		ExInitializeFastMutex(&m_ProcessesLinkedListMutex);
		m_Pool = pool;
		m_Tag = tag;
	}

	SingleLinkedList(_In_ CONST SingleLinkedList&) = delete;
	SingleLinkedList& operator=(_In_ CONST SingleLinkedList&) = delete;

	~SingleLinkedList()
	{
		PSINGLE_LIST_ENTRY pIndirect = nullptr;
		PPROCESS_LIST_INFO pTempEntry = nullptr;

		DbgPrint("SingleLinkedList D'tor called");

		ExAcquireFastMutex(&m_ProcessesLinkedListMutex);

		pIndirect = m_pProcessLinkedListHead->Next;
		while (nullptr != pIndirect)
		{
			pTempEntry = CONTAINING_RECORD(pIndirect, PROCESS_LIST_INFO, ListEntry);
			pIndirect = pIndirect->Next;
			delete pTempEntry;
			pTempEntry = nullptr;
		}
		delete m_pProcessLinkedListHead;
		m_pProcessLinkedListHead = nullptr;

		ExReleaseFastMutex(&m_ProcessesLinkedListMutex);
	}

	VOID AddProcessToLinkedList(
		_In_ CONST PWCHAR pszProcessName,
		_In_ CONST ULONG ulProcessId
	)
	{
		PPROCESS_LIST_INFO pProcessInfo = nullptr;
		PSINGLE_LIST_ENTRY *pIndirect = nullptr;

		if (nullptr == pszProcessName)
		{
			return;
		}

		pProcessInfo = (PPROCESS_LIST_INFO)new(PagedPool, 'DaOr') PROCESS_LIST_INFO;
		NT_ASSERT(pProcessInfo);

		RtlStringCbCopyW(pProcessInfo->pszProcessName, MAX_PROCESS_NAME_LENGTH, pszProcessName);
		pProcessInfo->ulProcessId = ulProcessId;
		pProcessInfo->bIsInjected = FALSE;

		ExAcquireFastMutex(&m_ProcessesLinkedListMutex);

		pIndirect = &m_pProcessLinkedListHead;
		while (nullptr != (*pIndirect)->Next)
		{
			pIndirect = &(*pIndirect)->Next;
		}
		(*pIndirect)->Next = &(pProcessInfo->ListEntry);
		(pProcessInfo->ListEntry).Next = nullptr;

		ExReleaseFastMutex(&m_ProcessesLinkedListMutex);
	}

	PSINGLE_LIST_ENTRY FindEntryByData(
		_In_ CONST PWCHAR pszProcessName,
		_In_ CONST ULONG ulProcessId
	)
	{
		PSINGLE_LIST_ENTRY pIndirect = nullptr;
		PPROCESS_LIST_INFO pTempEntry = nullptr;

		ExAcquireFastMutex(&m_ProcessesLinkedListMutex);
		pIndirect = m_pProcessLinkedListHead->Next;
		while (nullptr != pIndirect)
		{
			pTempEntry = CONTAINING_RECORD(pIndirect, PROCESS_LIST_INFO, ListEntry);
			if ((ulProcessId == pTempEntry->ulProcessId) &&
				StringNCompare(pszProcessName, pTempEntry->pszProcessName, MAX_PROCESS_NAME_LENGTH))
			{
				ExReleaseFastMutex(&m_ProcessesLinkedListMutex);
				return pIndirect;
			}
			pIndirect = pIndirect->Next;
		}
		ExReleaseFastMutex(&m_ProcessesLinkedListMutex);

		return nullptr;
	}

	VOID RemoveEntryByData(
		_In_ CONST PWCHAR pszProcessName,
		_In_ CONST ULONG ulProcessId
	)
	{
		PSINGLE_LIST_ENTRY *pIndirect = nullptr;
		PSINGLE_LIST_ENTRY pEntryToRemove = nullptr;
		PPROCESS_LIST_INFO pTempEntry = nullptr;

		//Find the entry to remove
		pEntryToRemove = FindEntryByData(pszProcessName, ulProcessId);
		if (nullptr == pEntryToRemove)
		{
			return;
		}

		ExAcquireFastMutex(&m_ProcessesLinkedListMutex);

		// Point to the memory base of the allocated memory
		pTempEntry = CONTAINING_RECORD(pEntryToRemove, PROCESS_LIST_INFO, ListEntry);

		//Remove from Linked List
		pIndirect = &m_pProcessLinkedListHead->Next;
		while (*pIndirect != pEntryToRemove)
		{
			pIndirect = &(*pIndirect)->Next;
		}
		*pIndirect = pEntryToRemove->Next;

		ExReleaseFastMutex(&m_ProcessesLinkedListMutex);

		delete pTempEntry;
		pTempEntry = nullptr;
	}

	PSINGLE_LIST_ENTRY m_pProcessLinkedListHead = nullptr;
	FAST_MUTEX m_ProcessesLinkedListMutex = { 0 };
	POOL_TYPE m_Pool = PagedPool;
	ULONG m_Tag = 'DaOr';
};