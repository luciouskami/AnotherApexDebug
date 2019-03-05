#include <util.h>

namespace util
{
	void BypassCheckSign(PDRIVER_OBJECT a_driver_object)
	{
		//STRUCT FOR WIN64
		typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
		{
			struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
			struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
			struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
			void*        DllBase;
			void*        EntryPoint;
			ULONG32      SizeOfImage;
			UINT8        _PADDING0_[0x4];
			struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
			struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
			ULONG32      Flags;
		}LDR_DATA, *PLDR_DATA;
		PLDR_DATA v_ldr;
		v_ldr = static_cast<PLDR_DATA>(a_driver_object->DriverSection);
		v_ldr->Flags |= 0x20;
	}

	//TODO:
	//重写util函数
	//枚举驱动
	//_Use_decl_annotations_ auto EnumDriver(std::vector<wdk::_MEMORY_IMAGE_INFORMATION> &a_system_module) -> NTSTATUS
	//{
	//	PAGED_CODE();
	//	auto v_ret_status{ STATUS_SUCCESS };
	//	wdk::ZwQuerySystemInformation(wdk::SYSTEM_INFORMATION_CLASS::SystemModuleInformation,)

	//	return v_ret_status;
	//}
	_Use_decl_annotations_ auto EnumKernelModuleThreads(wchar_t* a_kernel_module_name, std::vector<CLIENT_ID> &a_thread_vec) -> bool
	{
		NTSTATUS a_ret_status;
		size_t v_size = 0x20000;
		size_t v_returned_size = 0;
		std::unique_ptr<uint8_t[]> v_buffer;

		a_thread_vec.clear();
		do
		{
			v_buffer.reset(new uint8_t[(v_size + 7) / 8 * 8]);
			a_ret_status = wdk::ZwQuerySystemInformation(wdk::SYSTEM_INFORMATION_CLASS::SystemProcessInformation, v_buffer.get(), v_size, reinterpret_cast<PULONG>(&v_returned_size));
			if (a_ret_status == STATUS_INFO_LENGTH_MISMATCH)
			{
				v_size = v_returned_size;

			}

		} while (a_ret_status == STATUS_INFO_LENGTH_MISMATCH);
		if (a_ret_status != 0)
		{
			return false;
		}
		for (size_t v_offset = 0; v_offset < v_returned_size;)
		{
			auto v_psi = reinterpret_cast<wdk::SYSTEM_PROCESS_INFORMATION*>(v_buffer.get() + v_offset);
			if (v_psi->ImageName.Buffer != nullptr)
			{
				if (std::wstring_view(v_psi->ImageName.Buffer).find(a_kernel_module_name) != std::wstring_view::npos)
				{
					while (v_psi->NumberOfThreads > 0)
					{
						wdk::PSYSTEM_THREAD_INFORMATION v_pthread_info = &v_psi->Threads[--v_psi->NumberOfThreads];
						a_thread_vec.emplace_back(v_pthread_info->ClientId);
					}
				}
			}
			if (v_psi->NextEntryOffset == 0)
			{
				break;
			}
			v_offset += v_psi->NextEntryOffset;
		}
		return true;
	}
	//这几个代码是抄BDBIG的,我那代码耦合性有点高，不好摘，先抄他的，能跑起来，然后再解耦合。
	NTSTATUS QuerySystemProcessInformation(wdk::PSYSTEM_PROCESS_INFORMATION* SystemInfo)
	{
		wdk::PSYSTEM_PROCESS_INFORMATION pBuffer = nullptr;
		ULONG BufferSize = 0;
		ULONG RequiredSize = 0;

		NTSTATUS v_ret_status = STATUS_SUCCESS;
		while ((v_ret_status = wdk::ZwQuerySystemInformation(
			wdk::SYSTEM_INFORMATION_CLASS::SystemProcessInformation,
			pBuffer,
			BufferSize,
			&RequiredSize//retn Length
		)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			BufferSize = RequiredSize;
			pBuffer = static_cast<wdk::PSYSTEM_PROCESS_INFORMATION>(ExAllocatePool(PagedPool, BufferSize));
		}

		if (!NT_SUCCESS(v_ret_status))
		{
			if (pBuffer != NULL)
			{
				ExFreePool(pBuffer);
			}

			return v_ret_status;
		}
		*SystemInfo = pBuffer;
		return v_ret_status;
	}
	auto EnumProcessThreads(HANDLE a_process_id, std::vector<CLIENT_ID> &a_thread_vec) -> bool
	{

		NTSTATUS a_ret_status;
		size_t v_size = 0x20000;
		size_t v_returned_size = 0;
		std::unique_ptr<uint8_t[]> v_buffer;

		a_thread_vec.clear();
		do
		{
			v_buffer.reset(new uint8_t[(v_size + 7) / 8 * 8]);
			a_ret_status = wdk::ZwQuerySystemInformation(wdk::SYSTEM_INFORMATION_CLASS::SystemProcessInformation, v_buffer.get(), v_size, reinterpret_cast<PULONG>(&v_returned_size));
			if (a_ret_status == STATUS_INFO_LENGTH_MISMATCH)
			{
				v_size = v_returned_size;

			}

		} while (a_ret_status == STATUS_INFO_LENGTH_MISMATCH);
		if (a_ret_status != 0)
		{
			return false;
		}
		for (size_t v_offset = 0; v_offset < v_returned_size;)
		{
			auto v_psi = reinterpret_cast<wdk::SYSTEM_PROCESS_INFORMATION*>(v_buffer.get() + v_offset);
			if (v_psi->ImageName.Buffer != nullptr)
			{
				if (v_psi->UniqueProcessId == a_process_id)
				{
					while (v_psi->NumberOfThreads > 0)
					{
						wdk::PSYSTEM_THREAD_INFORMATION v_pthread_info = &v_psi->Threads[--v_psi->NumberOfThreads];
						a_thread_vec.emplace_back(v_pthread_info->ClientId);
					}
				}
			}
			if (v_psi->NextEntryOffset == 0)
			{
				break;
			}
			v_offset += v_psi->NextEntryOffset;
		}
		return true;
	}
	void GetSystemModuleBase(char* a_module_name, ULONG64* a_ref_base, ULONG* a_buffer_size)
	{
		ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
		PVOID pBuffer = nullptr;
		PCHAR pDrvName = nullptr;
		NTSTATUS v_ret_status = { STATUS_UNSUCCESSFUL };
		PRTL_MODULES v_modules;
		do
		{
			pBuffer = kmalloc(BufferSize);
			if (pBuffer == nullptr)
				return;
			v_ret_status = wdk::ZwQuerySystemInformation(wdk::SYSTEM_INFORMATION_CLASS::SystemModuleInformation, pBuffer, BufferSize, &NeedSize);
			if (v_ret_status == STATUS_INFO_LENGTH_MISMATCH)
			{
				kfree(pBuffer);
				BufferSize *= 2;
			}
			else if (!NT_SUCCESS(v_ret_status))
			{
				kfree(pBuffer);
				return;
			}
		} while (v_ret_status == STATUS_INFO_LENGTH_MISMATCH);
		v_modules = static_cast<PRTL_MODULES>(pBuffer);
		ModuleCount = v_modules->NumberOfModules;
		for (i = 0; i < ModuleCount; i++)
		{
			if (reinterpret_cast<ULONG64>(v_modules->Modules[i].ImageBase) > static_cast<ULONG64>(0x8000000000000000))
			{
				pDrvName = reinterpret_cast<char*>(v_modules->Modules[i].FullPathName);
				if (std::string_view(pDrvName).find(a_module_name) != std::string_view::npos)
				{
					*a_ref_base = reinterpret_cast<ULONG64>(v_modules->Modules[i].ImageBase);
					*a_ref_base = v_modules->Modules[i].ImageSize;
					goto exit_sub;
				}
			}
		}
	exit_sub:
		kfree(pBuffer);
	}
	_Use_decl_annotations_ auto HidePCHDriverDepsSelf(PDRIVER_OBJECT a_self_driver_object) -> NTSTATUS
	{
		//为了辅助分析，应借助PCHunter的力量，所以我们加载的时候先判断PCHunter的驱动是否加载,
		//如果PCHunter的驱动已经被加载，那么我们对它进行隐藏，以躲避EAC的扫描
		//使用自身的druver_section来定位PCHunter的driver_section
		PAGED_CODE()
		auto v_ret_status{ STATUS_SUCCESS };
		auto v_self_entry = static_cast<wdk::PKLDR_DATA_TABLE_ENTRY>(a_self_driver_object->DriverSection);
		wdk::PKLDR_DATA_TABLE_ENTRY	v_fist_entry = nullptr;
		UNICODE_STRING v_pch_sys_name = { 0 };
		wdk::PKLDR_DATA_TABLE_ENTRY v_target_entry{ nullptr };
		RtlInitUnicodeString(&v_pch_sys_name, L"PCHUNTER*");
		v_fist_entry = v_self_entry;

		__try {
			do
			{
				if (v_self_entry->BaseDllName.Buffer != nullptr)
				{
					if (FsRtlIsNameInExpression(&v_pch_sys_name, &v_self_entry->BaseDllName, TRUE, nullptr))
					{
						v_target_entry = v_self_entry;
						break;
					}
					v_self_entry = reinterpret_cast<wdk::PKLDR_DATA_TABLE_ENTRY>(v_self_entry->InLoadOrderLinks.Blink);
				}
			} while (v_self_entry->InLoadOrderLinks.Blink != reinterpret_cast<PLIST_ENTRY>(v_fist_entry));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return NULL;
		}

		if (v_target_entry)
		{
			//p_HideDriver(v_target_entry,0);
			const PLIST_ENTRY v_target_entry_pointer = &(v_target_entry->InLoadOrderLinks);
			RemoveEntryList(v_target_entry_pointer);
			//这里有个坑，感谢汇编兄帮我们踩了
			v_target_entry_pointer->Flink = nullptr;
			v_target_entry_pointer->Blink = nullptr;
		}
		return v_ret_status;
	}




}

namespace BDBig
{
	VOID SSDT::SSDT_Init()
	{
		GetKeServiceDescriptorTableAddrX64();
	}

	ULONG64 SSDT::GetSSDTFuncCurAddrByIndex(ULONG index)
	{

		LONG dwtmp = 0;
		ULONGLONG addr = 0;
		PULONG ServiceTableBase = NULL;
		if (KeServiceDescriptorTable != NULL) {
			ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
			dwtmp = ServiceTableBase[index];
			dwtmp = dwtmp >> 4;
			addr = ((LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase);//&0xFFFFFFF0;
		}
		return addr;
	}

	VOID SSDT::Un_SSDTClass()
	{
		this->KeServiceDescriptorTable = nullptr;
	}

	void SSDT::GetKeServiceDescriptorTableAddrX64()
	{
		PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
		PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
		PUCHAR i = NULL;
		UCHAR b1 = 0, b2 = 0, b3 = 0;
		ULONGLONG templong = 0;
		ULONGLONG addr = 0;
		for (i = StartSearchAddress; i < EndSearchAddress; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
			{
				b1 = *(i);
				b2 = *(i + 1);
				b3 = *(i + 2);
				if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
				{
					memcpy(&templong, i + 3, 4);
					addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
					break;
				}
			}
		}
		KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)addr;
	}

	ULONG64 GetSystemModuleBase(char* lpModuleName)
	{
		ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
		PVOID pBuffer = NULL;
		PCHAR pDrvName = NULL;
		NTSTATUS Result;
		util::PRTL_MODULES pSystemModuleInformation;
		do
		{
			pBuffer = kmalloc(BufferSize);
			if (pBuffer == NULL)
				return 0;
			Result = wdk::ZwQuerySystemInformation(wdk::SYSTEM_INFORMATION_CLASS::SystemModuleInformation, pBuffer, BufferSize, &NeedSize);
			if (Result == STATUS_INFO_LENGTH_MISMATCH)
			{
				kfree(pBuffer);
				BufferSize *= 2;
			}
			else if (!NT_SUCCESS(Result))
			{
				kfree(pBuffer);
				return 0;
			}
		} while (Result == STATUS_INFO_LENGTH_MISMATCH);
		pSystemModuleInformation = (util::PRTL_MODULES)pBuffer;
		ModuleCount = pSystemModuleInformation->NumberOfModules;

		for (i = 0; i < ModuleCount; i++)
		{
			if (reinterpret_cast<ULONG64>(pSystemModuleInformation->Modules[i].ImageBase) > static_cast<ULONG64>(0x8000000000000000))
			{
				pDrvName = reinterpret_cast<char*>(pSystemModuleInformation->Modules[i].FullPathName) + pSystemModuleInformation->Modules[i].OffsetToFileName;
				if (_stricmp(pDrvName, lpModuleName) == 0)
					return reinterpret_cast<ULONG64>(pSystemModuleInformation->Modules[i].ImageBase);
			}
		}
		kfree(pBuffer);
		return 0;
	}

	void GetSystemModuleBase(char* a_module_name, ULONG64* a_ref_base, ULONG* a_buffer_size)
	{
		ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
		PVOID pBuffer = nullptr;
		PCHAR pDrvName = nullptr;
		NTSTATUS v_ret_status = { STATUS_UNSUCCESSFUL };
		util::PRTL_MODULES v_modules;
		do
		{
			pBuffer = kmalloc(BufferSize);
			if (pBuffer == nullptr)
				return;
			v_ret_status = wdk::ZwQuerySystemInformation(wdk::SYSTEM_INFORMATION_CLASS::SystemModuleInformation, pBuffer, BufferSize, &NeedSize);
			if (v_ret_status == STATUS_INFO_LENGTH_MISMATCH)
			{
				kfree(pBuffer);
				BufferSize *= 2;
			}
			else if (!NT_SUCCESS(v_ret_status))
			{
				kfree(pBuffer);
				return;
			}
		} while (v_ret_status == STATUS_INFO_LENGTH_MISMATCH);
		v_modules = static_cast<util::PRTL_MODULES>(pBuffer);
		ModuleCount = v_modules->NumberOfModules;
		for (i = 0; i < ModuleCount; i++)
		{
			if (reinterpret_cast<ULONG64>(v_modules->Modules[i].ImageBase) > static_cast<ULONG64>(0x8000000000000000))
			{
				pDrvName = reinterpret_cast<char*>(v_modules->Modules[i].FullPathName);
				if (std::string_view(pDrvName).find(a_module_name) != std::string_view::npos)
				{
					*a_ref_base = reinterpret_cast<ULONG64>(v_modules->Modules[i].ImageBase);
					*a_ref_base = v_modules->Modules[i].ImageSize;
					goto exit_sub;
				}
			}
		}
	exit_sub:
		kfree(pBuffer);

	}
	NTSTATUS ApcpQuerySystemProcessInformation(wdk::PSYSTEM_PROCESS_INFORMATION * SystemInfo)
	{
		wdk::PSYSTEM_PROCESS_INFORMATION pBuffer = NULL;
		ULONG BufferSize = 0;
		ULONG RequiredSize = 0;

		NTSTATUS status = STATUS_SUCCESS;
		while ((status = wdk::ZwQuerySystemInformation(
			wdk::SYSTEM_INFORMATION_CLASS::SystemProcessInformation,
			pBuffer,
			BufferSize,
			&RequiredSize//retn Length
		)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			BufferSize = RequiredSize;
			pBuffer = (wdk::PSYSTEM_PROCESS_INFORMATION)ExAllocatePool(PagedPool, BufferSize);
		}

		if (!NT_SUCCESS(status))
		{
			if (pBuffer != NULL)
			{
				ExFreePool(pBuffer);
			}

			return status;
		}
		*SystemInfo = pBuffer;
		return status;
	}

	NTSTATUS GetProcessThreadInfo(IN ULONG Pid, OUT ULONG *ThreadNuber, OUT PULONG64 Tid, OUT PULONG64 StartAddr)
	{
		PEPROCESS pEProcess;
		wdk::PSYSTEM_PROCESS_INFORMATION OriginalSystemProcessInfo = NULL;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)Pid, &pEProcess);
		if (!NT_SUCCESS(status))
		{
			return status;
		}
		if (MmIsAddressValid(ThreadNuber) == 0)
		{
			status = STATUS_UNSUCCESSFUL;
			return status;
		}
		if (MmIsAddressValid(StartAddr) == 0)
		{
			status = STATUS_UNSUCCESSFUL;
			return status;
		}
		if (MmIsAddressValid(Tid) == 0)
		{
			status = STATUS_UNSUCCESSFUL;
			return status;
		}
		status = ApcpQuerySystemProcessInformation(&OriginalSystemProcessInfo);
		if (!NT_SUCCESS(status))
		{
			ObDereferenceObject(pEProcess);
			return status;
		}
		wdk::PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = OriginalSystemProcessInfo;
		status = STATUS_NOT_FOUND;
		do
		{
			if (SystemProcessInfo->UniqueProcessId == PsGetProcessId(pEProcess))
			{
				status = STATUS_SUCCESS;
				break;
			}

			SystemProcessInfo = (wdk::PSYSTEM_PROCESS_INFORMATION)((PUCHAR)SystemProcessInfo + SystemProcessInfo->NextEntryOffset);
		} while (SystemProcessInfo->NextEntryOffset != 0);

		if (!NT_SUCCESS(status))
		{
			ObDereferenceObject(pEProcess);
			ExFreePool(OriginalSystemProcessInfo);
			return status;
		}
		*ThreadNuber = SystemProcessInfo->NumberOfThreads;

		for (ULONG Index = 0; Index < SystemProcessInfo->NumberOfThreads; ++Index)
		{
			HANDLE UniqueThreadId = SystemProcessInfo->Threads[Index].ClientId.UniqueThread;
			Tid[Index] = (ULONG64)UniqueThreadId;
			StartAddr[Index] = (ULONG64)SystemProcessInfo->Threads[Index].StartAddress;
		}

		ObDereferenceObject(pEProcess);
		return status;
	}



	HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
	{
		OBJECT_ATTRIBUTES      ObjectAttributes = { 0, };
		CLIENT_ID              ClientId = { 0, };
		HANDLE                 hThread = NULL;
		NTSTATUS               Status;

		InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

		if (bInheritHandle) {
			ObjectAttributes.Attributes = OBJ_INHERIT;
		}

		ClientId.UniqueProcess = NULL;
		ClientId.UniqueThread = (HANDLE)dwThreadId;

		Status = wdk::ZwOpenThread(&hThread,
			dwDesiredAccess,
			&ObjectAttributes,
			&ClientId);
		return hThread;
	}

	NTSTATUS SuspendThread(HANDLE ThreadHandle)
	{
		SSDT                   _SSDT;
		NTSTATUS               Status;
		_SSDT.SSDT_Init();
		NtSuspendThread = (NTSTATUS(__cdecl *)(HANDLE, PULONG))_SSDT.GetSSDTFuncCurAddrByIndex(SSDT_NTSUSPENDTHRED);
		Status = NtSuspendThread(ThreadHandle, nullptr);
		_SSDT.Un_SSDTClass();
		return Status;
	}

	NTSTATUS ResumeThread(HANDLE hThread)
	{
		SSDT                   _SSDT;
		NTSTATUS               Status;
		_SSDT.SSDT_Init();
		NtResumeThread = (NTSTATUS(__cdecl *)(HANDLE, PULONG))_SSDT.GetSSDTFuncCurAddrByIndex(SSDT_RESUMETHREAD);
		Status = NtResumeThread(hThread, NULL);
		_SSDT.Un_SSDTClass();
		return Status;
	}

	NTSTATUS GetDriverThread(char * DriverName, OUT ULONG * ThreadNuber, OUT PULONG64 Tid)
	{
		ULONG64				DriverBaseAddr = 0;
		ULONG    			DriverSize = 0;
		ULONG				Number = 0;
		ULONG				Number1 = 0;
		ULONG64              __Tid[0x256] = { 0 };
		ULONG64              __ThreadStartAddr[0x256] = { 0 };
		NTSTATUS            Status = STATUS_UNSUCCESSFUL;
		PETHREAD			Et = NULL;
		ULONG               Count = 0;
		GetSystemModuleBase(DriverName, &DriverBaseAddr, &DriverSize);
		if (DriverBaseAddr == 0 || DriverSize == 0) {
			return Status;
		}
		Status = GetProcessThreadInfo(4, &Number, __Tid, __ThreadStartAddr);
		if (!NT_SUCCESS(Status)) {
			return Status;
		}
		for (ULONG i = 0; i < Number; i++)
		{
			if (__ThreadStartAddr[i] >= DriverBaseAddr)
			{
				if (__ThreadStartAddr[i] <= DriverBaseAddr + DriverSize)
				{
					Tid[Count] = __Tid[i];
					Count++;
				}
			}
		}
		*ThreadNuber = Count;
		return STATUS_SUCCESS;
	}
	
}
