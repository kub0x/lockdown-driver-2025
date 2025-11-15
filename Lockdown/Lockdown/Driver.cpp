#include <ntifs.h>

#define LOCKDOWN_DEVICE 0x8022

#define IOCTL_LOCKDOWN_HELLO CTL_CODE(LOCKDOWN_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

EX_CALLBACK_FUNCTION RegistryCallback;
LARGE_INTEGER cmCookie = { 0 };
PVOID obCookie = 0;
PVOID ivCookie = 0;

_Use_decl_annotations_
NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {

	UNREFERENCED_PARAMETER(CallbackContext);

	NTSTATUS status = STATUS_SUCCESS;

	REG_NOTIFY_CLASS regOp = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	switch (regOp) {
	case RegNtPreSaveKey:

		REG_SAVE_KEY_INFORMATION* keyInfo = (REG_SAVE_KEY_INFORMATION*)Argument2;

		if (!keyInfo || !keyInfo->Object)
			break;

		PCUNICODE_STRING keyName = { 0 };

		status = CmCallbackGetKeyObjectIDEx(&cmCookie, keyInfo->Object, 0, &keyName, 0);
		if (!NT_SUCCESS(status)) {
			KdPrint(("Failed to parse registry key\n"));
			status = STATUS_OBJECT_PATH_NOT_FOUND;
			break;
		}

		UNICODE_STRING SAM = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SAM");
		UNICODE_STRING SECURITY = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SECURITY");
		UNICODE_STRING SYSTEM = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM");

		if (RtlPrefixUnicodeString(&SAM, keyName, TRUE) || RtlPrefixUnicodeString(&SECURITY, keyName, TRUE) || RtlPrefixUnicodeString(&SYSTEM, keyName, TRUE)) {

			KdPrint(("[Cm Cb] Blocked hive export attempt on key %wZ", keyName));
		}

		status = STATUS_ACCESS_DENIED;

	break;
	}

	return status;
}

OB_PREOP_CALLBACK_STATUS ObPreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);

	return OB_PREOP_SUCCESS;
}

VOID CreateProcessCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
	UNREFERENCED_PARAMETER(Process);
	
	if (CreateInfo) {
		// proceso se esta creando
		HANDLE pidRealParent = CreateInfo->CreatingThreadId.UniqueProcess;
		HANDLE pidParent = CreateInfo->ParentProcessId;

		if (pidParent != pidRealParent) {
			KdPrint(("[Process Cb] Process PPID spoofing detected, real pid %d presented pid %d\n", HandleToUlong(pidParent), HandleToUlong(pidRealParent)));
		}

		KdPrint(("[Process Cb] Process creation for image %wZ cmdLine %wZ\n", CreateInfo->ImageFileName, CreateInfo->CommandLine));

	}
	else {
		// proceso se esta destruyendo
		KdPrint(("[Process Cb] Process terminating %d\n", HandleToUlong(ProcessId)));
	}

}

VOID CreateThreadCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);
}

VOID LoadImageCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	UNREFERENCED_PARAMETER(ImageInfo);

	KdPrint(("[Load Image Cb] Image loading name %wZ in pid %d\n", FullImageName, HandleToUlong(ProcessId)));

}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

void LockdownUnload(PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\LOCKDOWNDRV");

	NTSTATUS status = IoDeleteSymbolicLink(&symLink);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot delete Symbolic Link 0x%08x\n", status));
	}

	ObUnRegisterCallbacks(obCookie);

	status = CmUnRegisterCallback(cmCookie);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot unregister registry callback 0x%08x\n", status));
	}

	status = PsRemoveLoadImageNotifyRoutine(LoadImageCallback);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot unregister load image callback 0x%08x\n", status));
	}

	status = PsRemoveCreateThreadNotifyRoutine(CreateThreadCallback);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot unregister thread callback 0x%08x\n", status));
	}

	status = PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems, CreateProcessCallback, TRUE);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot unregister process callback 0x%08x\n", status));
	}

	IoDeleteDevice(DriverObject->DeviceObject);

	KdPrint(("Lockdown unloaded\n"));

}

NTSTATUS LockdownCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	return CompleteRequest(Irp);
}

NTSTATUS LockdownDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	KdPrint(("Device Control called\n"));

	if (Irp->RequestorMode != UserMode) return STATUS_INVALID_DEVICE_REQUEST;

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	auto ioCtl = IrpSp->Parameters.DeviceIoControl;

	PUCHAR buffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR len = 0;

	switch (ioCtl.IoControlCode) {
	case IOCTL_LOCKDOWN_HELLO: {

		KdPrint(("[Dev Ioctl] Received from usermode %s\n", buffer));
		
		UCHAR out[] = "Hello from kernel\n";

		memcpy(buffer, out, sizeof(out));

		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	return CompleteRequest(Irp, status, len);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING DriverKey) {

	UNREFERENCED_PARAMETER(DriverKey);

	PDEVICE_OBJECT DeviceObject = 0;
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\LOCKDOWNDRV");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\LOCKDOWNDRV");
	UNICODE_STRING regAltitude = RTL_CONSTANT_STRING(L"12345.161");

	OB_CALLBACK_REGISTRATION obCallbacks = { 0 };
	OB_OPERATION_REGISTRATION opReg[2] = { 0 };

	opReg[0].ObjectType = PsProcessType;
	opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg[0].PreOperation = ObPreOperationCallback;

	opReg[1].ObjectType = PsThreadType;
	opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg[1].PreOperation = ObPreOperationCallback;

	obCallbacks.Altitude = RTL_CONSTANT_STRING(L"12345.212");
	obCallbacks.Version = OB_FLT_REGISTRATION_VERSION;
	obCallbacks.OperationRegistrationCount = 2;
	obCallbacks.OperationRegistration = opReg;

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot create Device 0x%08x\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot create Symbolic Link 0x%08x\n", status));
		return status;
	}

	status = CmRegisterCallbackEx(RegistryCallback, &regAltitude, DriverObject, 0, &cmCookie, 0);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot register registry callback 0x%08x\n", status));
	}

	status = PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems, CreateProcessCallback, FALSE);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot register process callback 0x%08x\n", status));
	}

	status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifySubsystems, CreateThreadCallback);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot register thread callback 0x%08x\n", status));
	}

	status = PsSetLoadImageNotifyRoutineEx(LoadImageCallback, PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot register load image callback 0x%08x\n", status));
	}

	status = ObRegisterCallbacks(&obCallbacks, &obCookie);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Cannot register OB callbacks 0x%08x\n", status));
	}

	KdPrint(("Lockdown driver loaded\n"));

	DriverObject->DriverUnload = LockdownUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = LockdownCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = LockdownCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LockdownDeviceControl;

	return STATUS_SUCCESS;
}