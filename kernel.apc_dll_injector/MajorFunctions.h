#pragma once


NTSTATUS CreateDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
);

NTSTATUS CloseDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
);

NTSTATUS UnsupportedFunctions(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
);

NTSTATUS WriteDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP pIrp
);

NTSTATUS ReadDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP pIrp
);