#include "Definitions.h"
#include "ShellCode.h"
#include "StringsUtils.h"
#include "MemoryHandler.h"
#include "ProcessesLinkedList.cpp"
#include "ApcInjectionHandler.h"

struct SingleLinkedList *pProcessLinkedList = nullptr;
// The injected DLL path should be read from Registry or IOCTL  
PWCHAR pszDllToInject = L"C:\\Users\\Windows7-x86\\Desktop\\test.dll";

BOOLEAN IsProcessInInjectionList(
	_In_ CONST PCHAR pszProcessName
)
{
	// Should iterate over processes list read from Registry or IOCTL.
	if (NULL == pszProcessName)
	{
		return FALSE;
	}
	return StringNCompare(pszProcessName, "test.target_pr", GetStringLength("test.target_pr"));
}

void PcreateProcessNotifyRoutineEx(
	_In_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	PCHAR pszProcessNameA = nullptr;
	WCHAR pszProcessNameW[MAX_PROCESS_NAME_LENGTH] = { 0 };
	size_t pcbProcessNameLength = 0;
	BOOLEAN bIsOnList = FALSE;

	pszProcessNameA = (PCHAR)PsGetProcessImageFileName(Process);
	bIsOnList = IsProcessInInjectionList(pszProcessNameA);

	if (NULL == CreateInfo || FALSE == bIsOnList)
	{
		if (TRUE == bIsOnList)
		{
			DbgPrint("Removing %s [%d] from list", pszProcessNameA, ProcessId);
			RtlStringCbLengthA(
				(STRSAFE_PCNZCH)pszProcessNameA,
				MAX_PROCESS_NAME_LENGTH,
				&pcbProcessNameLength
			);
			RtlMultiByteToUnicodeN(
				pszProcessNameW, MAX_PROCESS_NAME_LENGTH * 2, 
				NULL, 
				pszProcessNameA,
				pcbProcessNameLength
			);
			pProcessLinkedList->RemoveEntryByData(pszProcessNameW, (ULONG)ProcessId);
		}
		return;
	}

	RtlStringCbLengthA(
		(STRSAFE_PCNZCH)pszProcessNameA,
		MAX_PROCESS_NAME_LENGTH,
		&pcbProcessNameLength
	);
	RtlMultiByteToUnicodeN(
		pszProcessNameW, 
		MAX_PROCESS_NAME_LENGTH * 2, 
		NULL, 
		pszProcessNameA,
		pcbProcessNameLength
	);
	DbgPrint("Adding %s [%d] to list", pszProcessNameA, ProcessId);
	pProcessLinkedList->AddProcessToLinkedList(pszProcessNameW, (ULONG)ProcessId);

	UNREFERENCED_PARAMETER(ProcessId);
		
}

void NTAPI KernelRoutine(PKAPC apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePool(apc);
}

BOOLEAN GetSystemProcessInfoById(
	_In_ CONST HANDLE ProcessId,
	_Out_ PSYSTEM_PROCESS_INFO SysProcInfo
)
{
	PSYSTEM_PROCESS_INFO pSystemInformation = NULL;
	PVOID pSystemInformationBuffer = NULL;
	BOOLEAN bAnswer = FALSE;
	ULONG SystemInformationLength = 0;
	CONST ULONG SystemProcessInformation = 5;

	if (NULL == SysProcInfo)
	{
		bAnswer = FALSE;
		goto FinalStage;
	}

	// Get the process list length
	ZwQuerySystemInformation(SystemProcessInformation, pSystemInformationBuffer, SystemInformationLength, &SystemInformationLength);
	if ( 0 == SystemInformationLength)
	{
		DbgPrint("Error: Unable to query process thread list length.");
		bAnswer = FALSE;
		goto FinalStage;
	}

	pSystemInformationBuffer = ExAllocatePool(NonPagedPool, SystemInformationLength); // Allocate SystemInformationLengthmemory for the system information
	if (NULL == pSystemInformationBuffer)
	{
		DbgPrint("Error: Unable to allocate memory for the process thread list.");
		bAnswer = FALSE;
		goto FinalStage;
	}

	// Get the process thread list
	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, pSystemInformationBuffer, SystemInformationLength, &SystemInformationLength)))
	{
		DbgPrint("Error: Unable to query process thread list.");
		bAnswer = FALSE;
		goto FinalStage;
	}

	pSystemInformation = (PSYSTEM_PROCESS_INFO)pSystemInformationBuffer;

	// Find a target thread
	while (TRUE)
	{
		if (ProcessId == pSystemInformation->UniqueProcessId)
		{
			DbgPrint("Target thread found. TID: %d", pSystemInformation->Threads[0].ClientId.UniqueThread);
			(*SysProcInfo) = (*pSystemInformation);
			bAnswer = TRUE;
			break;
		}
		if (0 == pSystemInformation->NextEntryOffset)
		{
			bAnswer = FALSE;
			break;
		}
		pSystemInformation = (PSYSTEM_PROCESS_INFO)((PUCHAR)pSystemInformation + pSystemInformation->NextEntryOffset);
	}

FinalStage:

	if (NULL != pSystemInformationBuffer)
	{
		ExFreePool(pSystemInformationBuffer);
	}

	return bAnswer;
}

VOID InjectDllKernelApc(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	DbgPrint("InjectDll Entered");

	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PWCHAR pModulePath = (PWCHAR)NormalContext;
	ULONG ulSize = PAGE_SIZE;
	PKAPC pKapc;
	PINJECT_SHELL pInjectCode = nullptr;
	size_t cbModulePathLength = 0;

	if (nullptr == pModulePath)
	{
		DbgPrint("InjectDll - pModulePath is null");
	}

	// Allocate memory in the target process
	if (!NT_SUCCESS(ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pInjectCode, 0, &ulSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
	{
		DbgPrint("Error: Unable to allocate memory in the target process.");
		return;
	}
	DbgPrint("Memory allocated at %#x", pInjectCode);

	RtlStringCbLengthW(
		pModulePath,
		MAX_PATH,
		&cbModulePathLength
	);
	pInjectCode->Length = (USHORT)cbModulePathLength;
	pInjectCode->MaximumLength = (USHORT)(cbModulePathLength + 2);
	RtlCopyMemory(&(pInjectCode->DllName), pModulePath, (cbModulePathLength + 1) * 2); // Initialize the "UNICODE_STRING structure"
	pInjectCode->Buffer = (PWSTR)(&(pInjectCode->DllName));

	RtlCopyMemory(&(pInjectCode->ShellCode), ShellCode, sizeof(ShellCode)); // Copy the APC code to target process

	pInjectCode->ModuleFileName = &(pInjectCode->Length); //Pointer to the "IN PUNICODE_STRING ModuleFileName" parameter of LdrLoadDll
	pInjectCode->Tag = 'DaOr'; // To check when free memory

	DbgPrint("APC code address: %#x", &(pInjectCode->ShellCode));

	pKapc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC)); // Allocate the APC object
	if (!pKapc)
	{
		DbgPrint("Error: Unable to allocate the APC object.");
		ulSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pInjectCode, &ulSize, MEM_RELEASE);  // Free the allocated memory
		return;
	}

	KeInitializeApc(pKapc, KeGetCurrentThread(), OriginalApcEnvironment, KernelRoutine, NULL, (PKNORMAL_ROUTINE)(&(pInjectCode->ShellCode)), UserMode, nullptr); // Initialize the APC
	
	DbgPrint("Inserting APC to target thread");
	if (!KeInsertQueueApc(pKapc, NULL, NULL, IO_NO_INCREMENT))
	{
		DbgPrint("Error: Unable to insert APC to target thread.");
		ulSize = 0;
		ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pInjectCode, &ulSize, MEM_RELEASE); // Free the allocated memory
		ExFreePool(pKapc); // Free the APC object
		return;
	}

	DbgPrint("InjectDllKernelApc exiting");
}

NTSTATUS InstallKernelModeApcToInjectDll()
{
	PRKAPC pKapc = nullptr;
	PETHREAD pThread = nullptr;

	pKapc = (PRKAPC)new(NonPagedPool) KAPC;
	if (nullptr == pKapc)
	{
		DbgPrint("InstallKernelModeApcToInjectDll Failed to allocate memory for the APC");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	pThread = KeGetCurrentThread();
	KeInitializeApc(pKapc, pThread,
		OriginalApcEnvironment,
		KernelRoutine, NULL,
		(PKNORMAL_ROUTINE)InjectDllKernelApc,
		KernelMode, (PVOID)pszDllToInject);
	if (!KeInsertQueueApc(pKapc, NULL, NULL, IO_NO_INCREMENT))
	{
		DbgPrint("InstallKernelModeApcToInjectDll Failed to insert APC");
		delete pKapc;
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		DbgPrint("InstallKernelModeApcToInjectDll APC delivered");
	}
	
	return STATUS_SUCCESS;
}

VOID PloadImageNotifyRoutine(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	PEPROCESS Process = NULL;
	PCHAR pTeb = nullptr;
	DWORD ArbitraryUserPointer = 0;
	PCHAR pszProcessNameA = nullptr;
	WCHAR pszProcessNameW[MAX_PROCESS_NAME_LENGTH] = { 0 };
	size_t pcbProcessNameLength = 0;
	PSINGLE_LIST_ENTRY pListEntry = nullptr;
	PPROCESS_LIST_INFO pProcessListInfo = nullptr;

	UNREFERENCED_PARAMETER(FullImageName);
	UNREFERENCED_PARAMETER(ImageInfo);

	__try
	{
		pTeb = (PCHAR)__readfsdword(0x18);
		ArbitraryUserPointer = *(DWORD*)(pTeb + 0x014);
	}
	__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		return;
	}
	if (0 == ArbitraryUserPointer)
	{
		return;
	}

	// If ArbitraryUserPointer points to kernel32.dll it means ntdll.dll is done loading.
	if (FALSE == IsStringEndWith((wchar_t*)ArbitraryUserPointer, L"\\kernel32.dll"))
	{
		return;
	}
	Process = PsGetCurrentProcess();
	pszProcessNameA = (PCHAR)PsGetProcessImageFileName(Process);
	// TO-DO: Check why the process name is 15 characters.
	if (FALSE == StringNCompare(pszProcessNameA, "test.target_pr", GetStringLength("test.target_pr")))
	{
		return;
	}
	RtlStringCbLengthA(
		(STRSAFE_PCNZCH)pszProcessNameA,
		MAX_PROCESS_NAME_LENGTH,
		&pcbProcessNameLength
	);
	RtlMultiByteToUnicodeN(pszProcessNameW, MAX_PROCESS_NAME_LENGTH * 2, NULL, pszProcessNameA, pcbProcessNameLength);
	DbgPrint("Process %d name: %ws", ProcessId, pszProcessNameW);
	pListEntry = pProcessLinkedList->FindEntryByData(pszProcessNameW, (ULONG)ProcessId);
	//NT_ASSERT(pListEntry);
	if (nullptr == pListEntry)
	{
		DbgPrint("No process %s [%d] was found in the list", pszProcessNameA, ProcessId);
		return;
	}
	pProcessListInfo = CONTAINING_RECORD(pListEntry, PROCESS_LIST_INFO, ListEntry);
	if (FALSE == pProcessListInfo->bIsInjected)
	{
		DbgPrint("Injecting Dll to %s [%d]", pszProcessNameA, ProcessId);
		if (!NT_SUCCESS(InstallKernelModeApcToInjectDll()))
		{
			DbgPrint("InstallKernelModeApcToInjectDll Failed");
		}
		pProcessListInfo->bIsInjected = TRUE;
	}
	else
	{
		DbgPrint("already injected Dll to %s [%d]", pszProcessNameA, ProcessId);
	}
	DbgPrint("PloadImageNotifyRoutine Exit");
}

NTSTATUS InitApcHooks()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	DbgPrint("InitApcHooks Entered");
#pragma warning (disable: 4291)
	pProcessLinkedList = (SingleLinkedList*)new(PagedPool, 'DaOr') SingleLinkedList();
#pragma warning (default: 4291)
	if (nullptr == pProcessLinkedList)
	{
		DbgPrint("InitApcHooks - ExAllocatePoolWithTag failed to allocate memory to pProcessLinkedList");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = PsSetCreateProcessNotifyRoutineEx(
		(PCREATE_PROCESS_NOTIFY_ROUTINE_EX)PcreateProcessNotifyRoutineEx,
		FALSE);
	if (STATUS_SUCCESS != ntStatus)
	{
		if (STATUS_INVALID_PARAMETER == ntStatus)
		{
			DbgPrint("InitApcHooks - PsSetCreateProcessNotifyRoutineEx returned STATUS_INVALID_PARAMETER");
		}
		else if (STATUS_ACCESS_DENIED == ntStatus)
		{
			DbgPrint("InitApcHooks - PsSetCreateProcessNotifyRoutineEx returned STATUS_ACCESS_DENIED");
		}
		else
		{
			DbgPrint("InitApcHooks - PsSetCreateProcessNotifyRoutineEx returned NTSTATUS=%ld");
		}
		return ntStatus;
	}
	DbgPrint("InitApcHooks - PcreateProcessNotifyRoutineEx registered");


	ntStatus = PsSetLoadImageNotifyRoutine(
		(PLOAD_IMAGE_NOTIFY_ROUTINE)PloadImageNotifyRoutine);
	if (STATUS_INSUFFICIENT_RESOURCES == ntStatus)
	{
		DbgPrint("InitApcHooks - PsSetLoadImageNotifyRoutine returned STATUS_INSUFFICIENT_RESOURCES");
		return ntStatus;
	}
	DbgPrint("InitApcHooks - PloadImageNotifyRoutine registered");
	return ntStatus;
}

NTSTATUS FinApcHooks()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	DbgPrint("FinApcHooks Entered");

	if (nullptr != pProcessLinkedList)
	{
		delete pProcessLinkedList;
		pProcessLinkedList = nullptr;
	}

	ntStatus = PsSetCreateProcessNotifyRoutineEx(
		(PCREATE_PROCESS_NOTIFY_ROUTINE_EX)PcreateProcessNotifyRoutineEx,
		TRUE);
	if (STATUS_SUCCESS != ntStatus)
	{
		if (STATUS_INVALID_PARAMETER == ntStatus)
		{
			DbgPrint("FinApcHooks - PsSetCreateProcessNotifyRoutineEx returned STATUS_INVALID_PARAMETER");
		}
		else
		{
			DbgPrint("FinApcHooks - PsSetCreateProcessNotifyRoutineEx returned STATUS_ACCESS_DENIED");
		}
		return ntStatus;
	}
	DbgPrint("FinApcHooks - PcreateProcessNotifyRoutineEx unregistered");

	ntStatus = PsRemoveLoadImageNotifyRoutine(
		(PLOAD_IMAGE_NOTIFY_ROUTINE)PloadImageNotifyRoutine
	);
	if (STATUS_PROCEDURE_NOT_FOUND == ntStatus)
	{
		DbgPrint("FinApcHooks - PsSetLoadImageNotifyRoutine returned STATUS_PROCEDURE_NOT_FOUND");
		return ntStatus;
	}
	DbgPrint("FinApcHooks - PloadImageNotifyRoutine unregistered");

	return ntStatus;
}