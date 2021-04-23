#pragma once

#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>

#define STATUS_ACCESS_DENIED 0xC0000022

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB
{
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE SpareBool;
    void *Mutant;
    void *ImageBaseAddress;
    void *Ldr;
    void *ProcessParameters;
    void *SubSystemData;
    void *ProcessHeap;
    void *FastPebLock;
    void *FastPebLockRoutine;
    void *FastPebUnlockRoutine;
    DWORD EnvironmentUpdateCount;
    void *KernelCallbackTable;
    DWORD SystemReserved[1];
    DWORD ExecuteOptions : 2; // bit offset: 34, len=2
    DWORD SpareBits : 30;     // bit offset: 34, len=30
    void *FreeList;
    DWORD TlsExpansionCounter;
    void *TlsBitmap;
    DWORD TlsBitmapBits[2];
    void *ReadOnlySharedMemoryBase;
    void *ReadOnlySharedMemoryHeap;
    void **ReadOnlyStaticServerData;
    void *AnsiCodePageData;
    void *OemCodePageData;
    void *UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    DWORD NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    DWORD HeapSegmentReserve;
    DWORD HeapSegmentCommit;
    DWORD HeapDeCommitTotalFreeThreshold;
    DWORD HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    void **ProcessHeaps;
    void *GdiSharedHandleTable;
    void *ProcessStarterHelper;
    DWORD GdiDCAttributeList;
    void *LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    DWORD ImageSubsystemMinorVersion;
    DWORD ImageProcessAffinityMask;
    DWORD GdiHandleBuffer[34];
    void (*PostProcessInitRoutine)();
    void *TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    DWORD SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    void *pShimData;
    void *AppCompatInfo;
    UNICODE_STRING CSDVersion;
    void *ActivationContextData;
    void *ProcessAssemblyStorageMap;
    void *SystemDefaultActivationContextData;
    void *SystemAssemblyStorageMap;
    DWORD MinimumStackCommit;
} PEB, *PPEB;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

NTSYSAPI NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
int ProcessHollowing(char *DestinationProgramPath, char *SourceProgramPath);