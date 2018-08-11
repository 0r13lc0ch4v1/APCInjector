#pragma once

#pragma pack(push, 1)
typedef struct _INJECT_SHELL
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
	WCHAR DllName[MAX_PATH];
	ULONG Tag;
	HANDLE ModuleHandle;
	PVOID ModuleFileName; 
	CHAR ShellCode;
}	INJECT_SHELL, *PINJECT_SHELL;
#pragma pack(pop)

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
}	KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	PRKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2
);

typedef KKERNEL_ROUTINE(NTAPI *PKKERNEL_ROUTINE);

typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(
	PRKAPC Apc
	);

VOID PloadImageNotifyRoutine(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
);

void PcreateProcessNotifyRoutineEx(
	_In_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

NTSTATUS InitApcHooks();

NTSTATUS FinApcHooks();

extern "C" void KeInitializeApc(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);

extern "C"  BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);

BOOLEAN GetSystemProcessInfoById(
	_In_ CONST HANDLE ProcessId,
	_Out_ PSYSTEM_PROCESS_INFO SysProcInfo
);