#pragma once
#pragma once
#ifndef NTDDI_VERSION
#define NTDDI_VERSION   NTDDI_WIN10
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT    _WIN32_WINNT_WIN10
#endif
#ifndef WINVER
#define WINVER          _WIN32_WINNT_WIN10
#endif

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#pragma warning(disable: 4100)   // 未引用形参
#pragma warning(disable: 4201)   // 匿名联合/结构体
#pragma warning(disable: 4214)   // 非int型位域
#pragma warning(disable: 4996)   // deprecated API警告

#define NTRELOAD_VERSION    "1.1"    // v1.1: 修正RIP相对寻址崩溃
#define DRIVER_POOL_FILE    'FTNT'   // RNT - 文件缓冲
#define DRIVER_POOL_MOD     'MTNT'   // RNT - 新模块内存
#define DRIVER_POOL_MISC    'XTNT'   // RNT - 杂项
#define TARGET_PID          4268    // 目标进程PID

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_      ULONG   SystemInformationClass,
    _Out_opt_ PVOID   SystemInformation,
    _In_      ULONG   SystemInformationLength,
    _Out_opt_ PULONG  ReturnLength
);

#define SystemModuleInformation  11UL

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG                          NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
typedef NTSTATUS(NTAPI* FN_PsLookupProcessByProcessId)(
    _In_  HANDLE     ProcessId,
    _Out_ PEPROCESS* Process
    );

typedef NTSTATUS(NTAPI* FN_PsTerminateProcess)(
    _In_ PEPROCESS Process,
    _In_ NTSTATUS  ExitStatus
    );

typedef NTSTATUS(NTAPI* FN_ZwTerminateProcess)(
    _In_opt_ HANDLE   ProcessHandle,
    _In_     NTSTATUS ExitStatus
    );

typedef struct _Rtl_MODULE {
    PVOID      NewBase;         // 新分配可执行内存基址
    SIZE_T     NewSize;         // = PE SizeOfImage
    PVOID      RawFileData;     // 磁盘原始文件缓冲
    SIZE_T     RawFileSize;
    ULONG_PTR  OldBase;         // 运行中老ntoskrnl真实基址
    ULONG      OldSize;
    ULONG_PTR  PreferredBase;   // PE OptionalHeader.ImageBase (编译时首选基址)
} Rtl_MODULE, * PRtl_MODULE;

extern Rtl_MODULE g_RtlMod;

PVOID      RtlFindRunningNtBase(_Out_ PULONG ImageSize);
NTSTATUS   RtlReadNtFromDisk(_Out_ PVOID* Buf, _Out_ PSIZE_T Size);
PVOID      RtlAllocAndMapPe(_In_ PVOID RawData, _In_opt_ PVOID OldNtBase,
    _Out_ PSIZE_T AllocSize);

PVOID      RtlGetExport(_In_ PVOID ModBase, _In_ PCSTR Name);
NTSTATUS   RtlTerminateViaNtModule(_In_ PVOID NewNtBase, _In_ ULONG Pid);
VOID       RtlCleanup(VOID);