#pragma warning(disable : 5040)

#include <etwhook_init.hpp>
#include <etwhook_manager.hpp>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

#define _countof(arr) (sizeof(arr) / sizeof(arr[0]))
#define POOL_TAG 'TSET'

static volatile LONG gHooksActive = 0;
static volatile LONG gCallStats[0x0200] = { 0 };
static volatile bool gIsUnloading = false;
static void* gStatsThread = nullptr;


#define SYSCALL_NtCreateUserProcess 0xC4  // Windows 10 1903

typedef NTSTATUS(NTAPI* PFN_NtCreateUserProcess)(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_opt_ PVOID ProcessParameters,
    _Inout_ PVOID CreateInfo,
    _In_opt_ PVOID AttributeList
    );

static PFN_NtCreateUserProcess OriginalNtCreateUserProcess = nullptr;
static ULONG g_NtCreateUserProcessSyscallIndex = 0;

EXTERN_C PCHAR PsGetProcessImageFileName(PEPROCESS Process);


static void GetProcessImageName(PEPROCESS pEProcess, WCHAR* outBuffer, ULONG bufferSize)
{
    if (!pEProcess || !outBuffer || bufferSize < sizeof(WCHAR))
    {
        if (outBuffer) RtlZeroMemory(outBuffer, bufferSize);
        return;
    }

    __try
    {
        PCHAR shortName = PsGetProcessImageFileName(pEProcess);
        if (shortName)
        {
            ANSI_STRING asShortName;
            RtlInitAnsiString(&asShortName, shortName);

            UNICODE_STRING usShortName = { 0 };
            NTSTATUS status = RtlAnsiStringToUnicodeString(&usShortName, &asShortName, TRUE);

            if (NT_SUCCESS(status))
            {
                RtlStringCbCopyW(outBuffer, bufferSize, usShortName.Buffer);
                RtlFreeUnicodeString(&usShortName);
                return;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LOG_ERROR("Exception in GetProcessImageName");
    }

    RtlStringCbCopyW(outBuffer, bufferSize, L"[Unknown]");
}

#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)

static NTSTATUS NTAPI DetourNtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags,
    _In_ ULONG ThreadFlags,
    _In_opt_ PVOID ProcessParameters,
    _Inout_ PVOID CreateInfo,
    _In_opt_ PVOID AttributeList
)
{
    // 调用原始函数
    NTSTATUS status = OriginalNtCreateUserProcess(
        ProcessHandle,
        ThreadHandle,
        ProcessDesiredAccess,
        ThreadDesiredAccess,
        ProcessObjectAttributes,
        ThreadObjectAttributes,
        ProcessFlags,
        ThreadFlags,
        ProcessParameters,
        CreateInfo,
        AttributeList
    );

    // 如果成功创建进程，检查是否是计算器
    if (NT_SUCCESS(status) && ProcessHandle && *ProcessHandle)
    {
        PEPROCESS pProcess = nullptr;

        NTSTATUS refStatus = ObReferenceObjectByHandle(
            *ProcessHandle,
            PROCESS_QUERY_LIMITED_INFORMATION,
            *PsProcessType,
            KernelMode,
            (PVOID*)&pProcess,
            nullptr
        );

        if (NT_SUCCESS(refStatus) && pProcess)
        {
            WCHAR processName[256] = { 0 };
            GetProcessImageName(pProcess, processName, sizeof(processName));

            HANDLE pid = PsGetProcessId(pProcess);

            // 检查是否是计算器
            if (wcsstr(processName, L"calc.exe") != NULL ||
                wcsstr(processName, L"Calculator.exe") != NULL ||
                wcsstr(processName, L"CalculatorApp.exe") != NULL)
            {
                LOG_INFO("[ProcessBlock] Terminating calculator: PID=%llu, Name=%ws",
                    (ULONG64)pid,
                    processName);

                // 终止进程
                ZwTerminateProcess(*ProcessHandle, STATUS_ACCESS_DENIED);

                // 关闭句柄
                ZwClose(*ProcessHandle);
                if (ThreadHandle && *ThreadHandle)
                {
                    ZwClose(*ThreadHandle);
                }

                ObDereferenceObject(pProcess);

                // 返回失败状态
                return STATUS_ACCESS_DENIED;
            }

            LOG_INFO("[ProcessCreate] PID=%llu, Name=%ws",
                (ULONG64)pid,
                processName);

            ObDereferenceObject(pProcess);
        }
    }

    return status;
}

static void __fastcall HookCallback(_In_ unsigned int systemCallIndex, _Inout_ void** systemCallFunction)
{
    if (systemCallIndex == g_NtCreateUserProcessSyscallIndex)
    {
        OriginalNtCreateUserProcess = (PFN_NtCreateUserProcess)*systemCallFunction;
        *systemCallFunction = (PVOID)DetourNtCreateUserProcess;
        EtwHookManager::GetInstance()->Notify(HookCallback);
    }
    
}

static void DriverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    gIsUnloading = true;
    LOG_INFO("Starting driver unload...");

    EtwHookManager* manager = EtwHookManager::GetInstance();
    if (manager)
        manager->Destory();

    LOG_INFO("Driver unloaded successfully");
}

// 驱动入口
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    driverObject->DriverUnload = DriverUnload;

    kstd::Logger::Initialize("etw_hook");

    LOG_INFO("========================================");
    LOG_INFO("Process Monitor Driver Started");
    LOG_INFO("Using ETW Hook for NtCreateUserProcess");
    LOG_INFO("========================================");

    // 设置 NtCreateUserProcess 的系统调用号
    g_NtCreateUserProcessSyscallIndex = SYSCALL_NtCreateUserProcess;
    LOG_INFO("Target syscall index: 0x%X (NtCreateUserProcess)", g_NtCreateUserProcessSyscallIndex);

    // 初始化 ETW Hook 管理器
    EtwHookManager* manager = EtwHookManager::GetInstance();
    if (manager)
    {
        NTSTATUS initStatus = manager->Notify(HookCallback);
        if (!NT_SUCCESS(initStatus))
        {
            LOG_ERROR("EtwHookManager initialize failed: 0x%X", initStatus);
            return initStatus;
        }
        LOG_INFO("ETW Hook Manager initialized successfully");
    }
    else
    {
        LOG_ERROR("Failed to get EtwHookManager instance");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}