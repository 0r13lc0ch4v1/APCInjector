#pragma once

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KeInject");
UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\KeInject");

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  pDriverObject,
	_In_ PUNICODE_STRING pRegistryPath
);

extern "C" VOID DeviceUnload(
	_In_ PDRIVER_OBJECT pDriverObject
);