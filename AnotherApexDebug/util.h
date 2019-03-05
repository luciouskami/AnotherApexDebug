#pragma once


extern "C"
{
#include <ntifs.h>
#include <ntintsafe.h>
#include <ntddk.h>
#include <intrin.h>
}
#include <memory>
#include <vector>
#include <Wdk.h>
namespace util
{
#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p) ExFreePool(_p)
	using PRTL_MODULES = wdk::PRTL_PROCESS_MODULES;
	using PFN_NTCBPROCESSINFORMATION = void(DWORD, PWSTR, USHORT);
	void BypassCheckSign(PDRIVER_OBJECT a_driver_object);

	//这个思路来源于Meesong，非常感谢他提供了functional的替代方案
	template<typename F>
	_Use_decl_annotations_ auto NtQuerySystemProcessInformation(F NtCBProcessInformation) -> bool
	{
		std::unique_ptr<uint8_t[]> v_buffer;
		size_t v_size = 0x20000;
		size_t v_returnedSize = 0;
		NTSTATUS v_ret_status;
		do {
			v_buffer.reset(new uint8_t[(v_size + 7) / 8 * 8]);
			v_ret_status = wdk::ZwQuerySystemInformation(wdk::SystemProcessInformation, v_buffer.get(), v_size, reinterpret_cast<PULONG>(&v_returnedSize));
			if (v_ret_status == STATUS_INFO_LENGTH_MISMATCH)
			{
				v_size = v_returnedSize;
			}
		} while (v_ret_status == STATUS_INFO_LENGTH_MISMATCH);

		if (v_ret_status != 0)
		{
			return false;
		}

		for (size_t offset = 0; offset < v_returnedSize;)
		{
			wdk::SYSTEM_PROCESS_INFORMATION* ptr = reinterpret_cast<wdk::SYSTEM_PROCESS_INFORMATION*>(v_buffer.get() + offset);
			if (ptr->ImageName.Buffer != nullptr)
			{
				NtCBProcessInformation(reinterpret_cast<DWORD>(ptr->UniqueProcessId), ptr->ImageName.Buffer, ptr->ImageName.Length);
			}
			if (ptr->NextEntryOffset == 0)
			{
				break;
			}
			offset += ptr->NextEntryOffset;
		}

		return true;
	}
	_Use_decl_annotations_ auto EnumKernelModuleThreads(wchar_t* a_kernel_module_name, std::vector<CLIENT_ID> &a_thread_vec) -> bool;
	_Use_decl_annotations_ void GetSystemModuleBase(char* lpModuleName, ULONG64* ByRefBase, ULONG* ByRefSize);
	_Use_decl_annotations_ auto QuerySystemProcessInformation(wdk::SYSTEM_PROCESS_INFORMATION* SystemInfo)->NTSTATUS;
	//_Use_decl_annotations_ auto EnumDriver(std::vector<wdk::_MEMORY_IMAGE_INFORMATION> &a_system_module)->NTSTATUS;
	_Use_decl_annotations_ auto HidePCHDriverDepsSelf(PDRIVER_OBJECT a_self_driver_object)->NTSTATUS;



}
namespace BDBig
{
	typedef struct _SYSTEM_SERVICE_TABLE {
		PVOID ServiceTableBase;
		PVOID ServiceCounterTableBase;
#if defined(_X86_)
		ULONG NumberOfServices;
#elif defined(_AMD64_)
		ULONG64	NumberOfServices;
#endif
		PVOID  		ParamTableBase;
	} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;
	class SSDT
	{
	public:
		VOID SSDT_Init();
		ULONG64 GetSSDTFuncCurAddrByIndex(ULONG index);
		VOID Un_SSDTClass();
	public:

		PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable = nullptr;
	private:
		void GetKeServiceDescriptorTableAddrX64();

	};

//硬编码需要修改
#define SSDT_NTSUSPENDTHRED 436
#define SSDT_RESUMETHREAD   82
//硬编码需要修改
	typedef int BOOL;
	static NTSTATUS
	(__fastcall *NtSuspendThread)(
		__in HANDLE ThreadHandle,
		__out_opt PULONG PreviousSuspendCount
		);


	static NTSTATUS
	(__fastcall *NtResumeThread)(
		__in HANDLE ThreadHandle,
		__out_opt PULONG PreviousSuspendCount
		);

	
	ULONG64 GetSystemModuleBase(char* lpModuleName);

	void GetSystemModuleBase(char* a_module_name, ULONG64* a_ref_base, ULONG* a_buffer_size);
	NTSTATUS ApcpQuerySystemProcessInformation(wdk::SYSTEM_PROCESS_INFORMATION * SystemInfo);
	/*
	   获取进程中线程的ET结构
	   参数1:进程PID
	   参数2:线程数
	   参数3:记录线程Tid的数组。
	   参数4：线程起始地址
	*/
	NTSTATUS GetProcessThreadInfo(IN ULONG Pid, OUT ULONG *ThreadNuber, OUT PULONG64 Tid, OUT PULONG64 StartAddr);



	HANDLE OpenThread(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwThreadId);

	NTSTATUS SuspendThread(__in HANDLE ThreadHandle);

	NTSTATUS ResumeThread(HANDLE hThread);

	NTSTATUS GetDriverThread(char *DriverName, OUT ULONG *ThreadNuber, OUT PULONG64 Tid);
	
}