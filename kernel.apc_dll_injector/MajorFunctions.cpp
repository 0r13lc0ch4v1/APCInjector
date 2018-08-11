#include "Definitions.h"
#include "MajorFunctions.h"


NTSTATUS CreateDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	DbgPrint("CreateDevice is called.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = FILE_OPENED;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS CloseDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	DbgPrint("CloseDevice is called.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS UnsupportedFunctions(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP			pIrp
)
{
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	DbgPrint("UnsupportedFunctions - Unsupported Major Function Requested. Returning STATUS_NOT_SUPPORTED.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS WriteDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP pIrp
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	DbgPrint("WriteDevice is called.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}

NTSTATUS ReadDevice(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP pIrp
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pDeviceObject);

	PAGED_CODE();

	DbgPrint("DriverRead is called.");

	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}
