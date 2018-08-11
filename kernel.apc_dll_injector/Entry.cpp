#include "Definitions.h"
#include "MajorFunctions.h"
#include "ApcInjectionHandler.h"
#include "Entry.h"

_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH CreateDevice;
_Dispatch_type_(IRP_MJ_CLOSE)  DRIVER_DISPATCH CloseDevice;
_Dispatch_type_(IRP_MJ_READ)   DRIVER_DISPATCH DriverRead;
_Dispatch_type_(IRP_MJ_WRITE)  DRIVER_DISPATCH DriverWrite;

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD     DeviceUnload;


NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  pDriverObject,
	_In_ PUNICODE_STRING pRegistryPath
)
{
	UINT32 uiIndex;

	UNREFERENCED_PARAMETER(pRegistryPath);

	DbgPrint("DriverEntry entered");

	NTSTATUS ret = STATUS_SUCCESS;
	ret = InitApcHooks();
	if (!NT_SUCCESS(ret))
	{
		return ret;
	}

	for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
	{
		pDriverObject->MajorFunction[uiIndex] = UnsupportedFunctions;
	}
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)CreateDevice;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = (PDRIVER_DISPATCH)CloseDevice;
	pDriverObject->MajorFunction[IRP_MJ_READ]   = (PDRIVER_DISPATCH)ReadDevice;
	pDriverObject->MajorFunction[IRP_MJ_WRITE]  = (PDRIVER_DISPATCH)WriteDevice;

	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)DeviceUnload;

	DbgPrint("DLL injection driver loaded.");
	return STATUS_SUCCESS;
}

VOID DeviceUnload(
	_In_ PDRIVER_OBJECT pDriverObject
)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	
	FinApcHooks();

	DbgPrint("DLL injection driver unloaded.");
}