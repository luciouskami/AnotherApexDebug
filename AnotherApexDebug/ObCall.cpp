#include <ObCall.h>

PVOID g_process_handle;
PVOID g_thread_handle;

OB_PREOP_CALLBACK_STATUS ProcessPreCall(PVOID /*RegistrationContext*/, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	if (pOperationInformation->ObjectType != *PsProcessType)
	{
		return OB_PREOP_SUCCESS;
	}
	if (strcmp(reinterpret_cast<char*>(wdk::PsGetProcessImageFileName(IoGetCurrentProcess())), EXE_NAME) == 0)
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE || pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
			pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0x1fffff;
		}
	}
	return OB_PREOP_SUCCESS;
}
auto RegisterProcessOb() -> NTSTATUS
{
	auto v_status{ STATUS_SUCCESS };
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = nullptr;
	RtlInitUnicodeString(&obReg.Altitude, L"25444");
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = static_cast<POB_PRE_OPERATION_CALLBACK>(ProcessPreCall);
	obReg.OperationRegistration = &opReg;
	v_status = ObRegisterCallbacks(&obReg, &g_process_handle);
	return v_status;
}
OB_PREOP_CALLBACK_STATUS ThreadPreCall(PVOID /*RegistrationContext*/, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	if (pOperationInformation->ObjectType != *PsThreadType)
	{
		return OB_PREOP_SUCCESS;
	}
	if (strcmp(reinterpret_cast<char*>(wdk::PsGetProcessImageFileName(IoGetCurrentProcess())), EXE_NAME) == 0)
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE || pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
			pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0x1fffff;
		}
	}
	return OB_PREOP_SUCCESS;
}
auto RegisterThreadOb() -> NTSTATUS
{
	auto v_status{ STATUS_SUCCESS };
	OB_CALLBACK_REGISTRATION v_ob_reg;
	OB_OPERATION_REGISTRATION op_reg;
	memset(&v_ob_reg, 0, sizeof(v_ob_reg));
	v_ob_reg.Version = ObGetFilterVersion();
	v_ob_reg.OperationRegistrationCount = 1;
	v_ob_reg.RegistrationContext = nullptr;
	RtlInitUnicodeString(&v_ob_reg.Altitude, L"25445");
	memset(&op_reg, 0, sizeof(op_reg));
	op_reg.ObjectType = PsThreadType;
	op_reg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	op_reg.PreOperation = static_cast<POB_PRE_OPERATION_CALLBACK>(ThreadPreCall);
	v_ob_reg.OperationRegistration = &op_reg;
	v_status = ObRegisterCallbacks(&v_ob_reg, &g_thread_handle);
	return v_status;
}
auto RegObCall() -> NTSTATUS
{
	auto v_status{ STATUS_SUCCESS };
	v_status = RegisterProcessOb();
	if (!NT_SUCCESS(v_status))
	{
		return v_status;
	}
	v_status = RegisterThreadOb();
	if (!NT_SUCCESS(v_status))
	{
		return v_status;
	}
	return v_status;
}

auto UnRegObCall() -> NTSTATUS
{
	auto v_status{ STATUS_SUCCESS };
	if (g_process_handle)
	{
		ObUnRegisterCallbacks(g_process_handle);
		g_process_handle = nullptr;
	}
	if (g_thread_handle)
	{
		ObUnRegisterCallbacks(g_thread_handle);
		g_thread_handle = nullptr;
	}
	return v_status;
}