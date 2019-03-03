#include <Driver.h>
extern "C"
{
#include <ntifs.h>
#include <ntintsafe.h>
#include <ntddk.h>
#include <intrin.h>
}

#include <Wdk.h>

extern "C" DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD DriverUnload;

_Use_decl_annotations_ static void DriverUnload(PDRIVER_OBJECT a_driver_object)
{
	//卸载例程
	UNREFERENCED_PARAMETER(a_driver_object);
	PAGED_CODE();
	//退出前必须要恢复EAC驱动的线程，且恢复必须要在游戏退出前，否则第二次启动游戏将失败，只能重启
}
_Use_decl_annotations_ auto DriverEntry(PDRIVER_OBJECT a_driver_object, \
	PUNICODE_STRING a_reg_path) -> NTSTATUS
{
	UNREFERENCED_PARAMETER(a_reg_path);
	PAGED_CODE();
	auto v_ret_status = STATUS_SUCCESS;
	for (;;)
	{
		//Thanks Meesong for WDKExt
		v_ret_status = wdk::WdkInitSystem();
		if (!NT_SUCCESS(v_ret_status))
		{
			break;
		}
		a_driver_object->DriverUnload = DriverUnload;
		break;
	}
	KdPrint(("load\n"));
	//为了辅助分析，应借助PCHunter的力量，所以我们加载的时候先判断PCHunter的驱动是否加载,
	//如果PCHunter的驱动已经被加载，那么我们对它进行隐藏，以躲避EAC的扫描
	return v_ret_status;

}