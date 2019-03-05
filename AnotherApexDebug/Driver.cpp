#include <Driver.h>
#include "ObCall.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD DriverUnload;
static HANDLE g_thread[20] = {nullptr };
static ULONG g_thread_num = 0;
_Use_decl_annotations_ static void DriverUnload(PDRIVER_OBJECT a_driver_object)
{
	//卸载例程
	UNREFERENCED_PARAMETER(a_driver_object);
	PAGED_CODE();
	//反注册OB
	UnRegObCall();
	//退出前必须要恢复EAC驱动的线程，且恢复必须要在游戏退出前，否则第二次启动游戏将失败，只能重启。
	for (ULONG i = 0; i < g_thread_num; i++)
	{
		BDBig::ResumeThread(g_thread[i]);
		ZwClose(g_thread);
	}
}
_Use_decl_annotations_ auto DriverEntry(PDRIVER_OBJECT a_driver_object, \
	PUNICODE_STRING a_reg_path) -> NTSTATUS
{
	UNREFERENCED_PARAMETER(a_reg_path);
	PAGED_CODE();
	auto v_ret_status = STATUS_SUCCESS;
	util::BypassCheckSign(a_driver_object);
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
	//多写两个个文件好了
	//隐藏PChunter的驱动
	util::HidePCHDriverDepsSelf(a_driver_object);
	//枚举线程以后暂停
	ULONG64 v_tid[0x256] = { 0 };
	BDBig::GetDriverThread("EasyAntiCheat.sys", &g_thread_num, v_tid);
	for (ULONG i = 0; i < g_thread_num; i++)
	{
		g_thread[i] = BDBig::OpenThread(THREAD_ALL_ACCESS, FALSE, reinterpret_cast<DWORD>(g_thread[i]));
		BDBig::SuspendThread(g_thread[i]);
	}
	//恢复读写权限
	RegObCall();
	//TODO:
	//Still work in progess
	//Remove EAC Obcall
	//Remove EAC Notify

	return v_ret_status;
}