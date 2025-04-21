// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//

#include <windows.h>
#include <inttypes.h>
#include <assert.h>
#include "minipal.h"
#include "minipal/cpufeatures.h"

#define HIDWORD(_qw)    ((ULONG)((_qw) >> 32))
#define LODWORD(_qw)    ((ULONG)(_qw))

#ifdef TARGET_64BIT
static const uint64_t MaxDoubleMappedSize = 2048ULL*1024*1024*1024;
#else
static const uint64_t MaxDoubleMappedSize = UINT_MAX;
#endif

#define VIRTUAL_ALLOC_RESERVE_GRANULARITY (64*1024)    // 0x10000  (64 KB)
inline size_t ALIGN_UP( size_t val, size_t alignment )
{
    // alignment must be a power of 2 for this implementation to work (need modulo otherwise)
    assert( 0 == (alignment & (alignment - 1)) );
    size_t result = (val + (alignment - 1)) & ~(alignment - 1);
    assert( result >= val );      // check for overflow
    return result;
}

template <typename T> inline T ALIGN_UP(T val, size_t alignment)
{
    return (T)ALIGN_UP((size_t)val, alignment);
}

inline void *GetTopMemoryAddress(void)
{
    static void *result; // = NULL;
    if( NULL == result )
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo( &sysInfo );
        result = sysInfo.lpMaximumApplicationAddress;
    }
    return result;
}

inline void *GetBotMemoryAddress(void)
{
    static void *result; // = NULL;
    if( NULL == result )
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo( &sysInfo );
        result = sysInfo.lpMinimumApplicationAddress;
    }
    return result;
}

#define TOP_MEMORY (GetTopMemoryAddress())
#define BOT_MEMORY (GetBotMemoryAddress())

bool VMToOSInterface::CreateDoubleMemoryMapper(void **pHandle, size_t *pMaxExecutableCodeSize)
{
    if (minipal_detect_rosetta())
    {
        // Rosetta doesn't support double mapping correctly. WINE on macOS ARM64 can be running under Rosetta.
        return false;
    }

    *pMaxExecutableCodeSize = (size_t)MaxDoubleMappedSize;
    *pHandle = CreateFileMapping(
                 INVALID_HANDLE_VALUE,    // use paging file
                 NULL,                    // default security
                 PAGE_EXECUTE_READWRITE |  SEC_RESERVE,  // read/write/execute access
                 HIDWORD(MaxDoubleMappedSize),                       // maximum object size (high-order DWORD)
                 LODWORD(MaxDoubleMappedSize),   // maximum object size (low-order DWORD)
                 NULL);

    return *pHandle != NULL;
}

void VMToOSInterface::DestroyDoubleMemoryMapper(void *mapperHandle)
{
    CloseHandle((HANDLE)mapperHandle);
}

void* VMToOSInterface::ReserveDoubleMappedMemory(void *mapperHandle, size_t offset, size_t size, const void *pMinAddr, const void* pMaxAddr)
{
    BYTE *pResult = nullptr;  // our return value;

    if (size == 0)
    {
        return nullptr;
    }

    //
    // First lets normalize the pMinAddr and pMaxAddr values
    //
    // If pMinAddr is NULL then set it to BOT_MEMORY
    if ((pMinAddr == 0) || (pMinAddr < (BYTE *) BOT_MEMORY))
    {
        pMinAddr = (BYTE *) BOT_MEMORY;
    }

    // If pMaxAddr is NULL then set it to TOP_MEMORY
    if ((pMaxAddr == 0) || (pMaxAddr > (BYTE *) TOP_MEMORY))
    {
        pMaxAddr = (BYTE *) TOP_MEMORY;
    }

    // If pMaxAddr is not greater than pMinAddr we can not make an allocation
    if (pMaxAddr <= pMinAddr)
    {
        return nullptr;
    }

    // If pMinAddr is BOT_MEMORY and pMaxAddr is TOP_MEMORY
    // then we can call ClrVirtualAlloc instead
    if ((pMinAddr == (BYTE *) BOT_MEMORY) && (pMaxAddr == (BYTE *) TOP_MEMORY))
    {
        return (BYTE*)MapViewOfFile((HANDLE)mapperHandle,
                        FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE,
                        HIDWORD((int64_t)offset),
                        LODWORD((int64_t)offset),
                        size);
    }

    // We will do one scan from [pMinAddr .. pMaxAddr]
    // First align the tryAddr up to next 64k base address.
    // See docs for VirtualAllocEx and lpAddress and 64k alignment for reasons.
    //
    BYTE *   tryAddr            = (BYTE *)ALIGN_UP((BYTE *)pMinAddr, VIRTUAL_ALLOC_RESERVE_GRANULARITY);
    bool     virtualQueryFailed = false;
    bool     faultInjected      = false;
    unsigned virtualQueryCount  = 0;

    // Now scan memory and try to find a free block of the size requested.
    while ((tryAddr + size) <= (BYTE *) pMaxAddr)
    {
        MEMORY_BASIC_INFORMATION mbInfo;

        // Use VirtualQuery to find out if this address is MEM_FREE
        //
        virtualQueryCount++;
        if (!VirtualQuery((LPCVOID)tryAddr, &mbInfo, sizeof(mbInfo)))
        {
            // Exit and return nullptr if the VirtualQuery call fails.
            virtualQueryFailed = true;
            break;
        }

        // Is there enough memory free from this start location?
        // Note that for most versions of UNIX the mbInfo.RegionSize returned will always be 0
        if ((mbInfo.State == MEM_FREE) &&
            (mbInfo.RegionSize >= (SIZE_T) size || mbInfo.RegionSize == 0))
        {
            // Try reserving the memory using VirtualAlloc now
            pResult = (BYTE*)MapViewOfFileEx((HANDLE)mapperHandle,
                        FILE_MAP_EXECUTE | FILE_MAP_READ | FILE_MAP_WRITE,
                        HIDWORD((int64_t)offset),
                        LODWORD((int64_t)offset),
                        size,
                        tryAddr);

            // Normally this will be successful
            //
            if (pResult != nullptr)
            {
                // return pResult
                break;
            }

            // We might fail in a race.  So just move on to next region and continue trying
            tryAddr = tryAddr + VIRTUAL_ALLOC_RESERVE_GRANULARITY;
        }
        else
        {
            // Try another section of memory
            tryAddr = max(tryAddr + VIRTUAL_ALLOC_RESERVE_GRANULARITY,
                          (BYTE*) mbInfo.BaseAddress + mbInfo.RegionSize);
        }
    }

    return pResult;
}

void *VMToOSInterface::CommitDoubleMappedMemory(void* pStart, size_t size, bool isExecutable)
{
    return VirtualAlloc(pStart, size, MEM_COMMIT, isExecutable ? PAGE_EXECUTE_READ : PAGE_READWRITE);
}

bool VMToOSInterface::ReleaseDoubleMappedMemory(void *mapperHandle, void* pStart, size_t offset, size_t size)
{
    LPVOID  result = VirtualAlloc(pStart, size, MEM_COMMIT, PAGE_READWRITE);
    assert(result != NULL);
    memset(pStart, 0, size);
    return UnmapViewOfFile(pStart);
}

void* VMToOSInterface::GetRWMapping(void *mapperHandle, void* pStart, size_t offset, size_t size)
{
    return (BYTE*)MapViewOfFile((HANDLE)mapperHandle,
                    FILE_MAP_READ | FILE_MAP_WRITE,
                    HIDWORD((int64_t)offset),
                    LODWORD((int64_t)offset),
                    size);
}

bool VMToOSInterface::ReleaseRWMapping(void* pStart, size_t size)
{
    return UnmapViewOfFile(pStart);
}

struct TemplateThunkMappingData
{
    typedef PVOID (*MapViewOfFile3_t)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
    MapViewOfFile3_t MapViewOfFile3 = NULL;
    typedef PVOID (*VirtualAlloc2_t)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
    VirtualAlloc2_t VirtualAlloc2 = NULL;
    typedef BOOL (*UnmapViewOfFileEx_t)(PVOID, ULONG);
    UnmapViewOfFileEx_t UnmapViewOfFileEx = NULL;
    HANDLE hFileMapping = NULL;
    LONG UsedSize = 0x10000; // The first 64KB is used for 
};

static TemplateThunkMappingData *volatile s_pThunkData = NULL;

TemplateThunkMappingData *InitializeTemplateThunkMappingData()
{
#ifdef TARGET_X86
    return NULL;
#else
    auto pThunkData = s_pThunkData;
    if (pThunkData != NULL)
    {
        return pThunkData;
    }

    pThunkData = new TemplateThunkMappingData();

    HMODULE kernel32 = LoadLibraryW(L"kernelbase.dll");
    if (kernel32 == NULL)
    {
        goto configDone;
    }
    HMODULE wincorememory = LoadLibraryW(L"api-ms-win-core-memory-l1-1-6.dll");
    if (wincorememory == NULL)
    {
        goto configDone;
    }

    pThunkData->MapViewOfFile3 = (TemplateThunkMappingData::MapViewOfFile3_t)GetProcAddress(wincorememory, "MapViewOfFile3");
    if (pThunkData->MapViewOfFile3 == NULL)
    {
        goto configDone;
    }
    pThunkData->VirtualAlloc2 = (TemplateThunkMappingData::VirtualAlloc2_t)GetProcAddress(wincorememory, "VirtualAlloc2");
    if (pThunkData->VirtualAlloc2 == NULL)
    {
        goto configDone;
    }
    pThunkData->UnmapViewOfFileEx = (TemplateThunkMappingData::UnmapViewOfFileEx_t)GetProcAddress(kernel32, "UnmapViewOfFileEx");
    if (pThunkData->UnmapViewOfFileEx == NULL)
    {
        goto configDone;
    }

    pThunkData->hFileMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE | SEC_COMMIT, 0, 0x10000, NULL);

configDone:

    if (kernel32 != NULL)
    {
        FreeLibrary(kernel32);
    }

    if (NULL != InterlockedCompareExchangePointer((PVOID*)&s_pThunkData, pThunkData, NULL))
    {
        delete pThunkData;
    }

    return s_pThunkData;
#endif
}

void* VMToOSInterface::CreateTemplate(void* pImageTemplate, size_t templateSize, void (*codePageGenerator)(uint8_t* pageBase, uint8_t* pageBaseRX, size_t size))
{
    auto pThunkData = InitializeTemplateThunkMappingData();
    if ((pThunkData == NULL) || pThunkData->hFileMapping == NULL)
    {
        return NULL;
    }

    LONG newValueForUsedSize = InterlockedAdd(&pThunkData->UsedSize, (LONG)templateSize);
    LONG oldValueForUsedSize = newValueForUsedSize - (LONG)templateSize;

    uint8_t* reservedRegion = (uint8_t*)pThunkData->VirtualAlloc2(GetCurrentProcess(), NULL, ALIGN_UP(templateSize, 0x10000), MEM_RESERVE_PLACEHOLDER | MEM_RESERVE, PAGE_NOACCESS, NULL, 0);
    BOOL splitPlaceholderResult = VirtualFree(reservedRegion, templateSize, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    if (!splitPlaceholderResult)
    {
        VirtualFree(reservedRegion, 0, MEM_RELEASE);
        return NULL;
    }

    void* mappedMemory = pThunkData->MapViewOfFile3(pThunkData->hFileMapping, GetCurrentProcess(), reservedRegion, (ULONG64)oldValueForUsedSize, templateSize, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
    void* result = NULL;
    if (mappedMemory != NULL)
    {
        codePageGenerator((uint8_t*)mappedMemory, (uint8_t*)mappedMemory, templateSize);
        BOOL unmapResult = UnmapViewOfFile(mappedMemory);
        assert(unmapResult);
        result = (void*)(uintptr_t)oldValueForUsedSize;
    }
    else
    {
        VirtualFree(reservedRegion, 0, MEM_RELEASE);
    }

    BOOL virtFreeResult = VirtualFree(reservedRegion + templateSize, 0, MEM_RELEASE);
    assert(virtFreeResult);

    return result;
}

bool VMToOSInterface::AllocateThunksFromTemplateRespectsStartAddress()
{
    return false;
}

void* VMToOSInterface::AllocateThunksFromTemplate(void* pTemplate, size_t templateSize, void* pStart)
{
    auto pThunkData = InitializeTemplateThunkMappingData();
    if ((pThunkData == NULL) || pThunkData->hFileMapping == NULL)
    {
        return NULL;
    }

    uint8_t* reservedRegion = (uint8_t*)pThunkData->VirtualAlloc2(GetCurrentProcess(), NULL, templateSize * 2, MEM_RESERVE_PLACEHOLDER | MEM_RESERVE, PAGE_NOACCESS, NULL, 0);
    if (reservedRegion == NULL)
    {
        return NULL;
    }

    BOOL splitPlaceholderResult = VirtualFree(reservedRegion, templateSize, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    if (!splitPlaceholderResult)
    {
        VirtualFree(reservedRegion, 0, MEM_RELEASE);
        return NULL;
    }

    void* mappedMemoryCode = pThunkData->MapViewOfFile3(pThunkData->hFileMapping, GetCurrentProcess(), reservedRegion, (ULONG64)pTemplate, templateSize, MEM_REPLACE_PLACEHOLDER, PAGE_EXECUTE_READ, NULL, 0);
    if (mappedMemoryCode == NULL)
    {
        VirtualFree(reservedRegion, 0, MEM_RELEASE);
        VirtualFree(reservedRegion + templateSize, 0, MEM_RELEASE);
        return NULL;
    }
    void* mappedMemoryData = pThunkData->MapViewOfFile3(pThunkData->hFileMapping, GetCurrentProcess(), reservedRegion + templateSize, 0, templateSize, MEM_REPLACE_PLACEHOLDER, PAGE_WRITECOPY, NULL, 0);
    if (mappedMemoryData == NULL)
    {
        pThunkData->UnmapViewOfFileEx(mappedMemoryCode, MEM_PRESERVE_PLACEHOLDER);
        VirtualFree(reservedRegion, 0, MEM_RELEASE);
        VirtualFree(reservedRegion + templateSize, 0, MEM_RELEASE);
    }

    return reservedRegion;
}

bool VMToOSInterface::FreeThunksFromTemplate(void* thunks, size_t templateSize)
{
    auto pThunkData = InitializeTemplateThunkMappingData();
    if ((pThunkData == NULL) || pThunkData->hFileMapping == NULL)
    {
        return false;
    }

    uint8_t* mappedMemoryCode = (uint8_t*)thunks;
    uint8_t* mappedMemoryData = mappedMemoryCode + templateSize;
    pThunkData->UnmapViewOfFileEx(mappedMemoryCode, MEM_PRESERVE_PLACEHOLDER);
    pThunkData->UnmapViewOfFileEx(mappedMemoryData, MEM_PRESERVE_PLACEHOLDER);
    VirtualFree(mappedMemoryCode, 0, MEM_RELEASE);
    VirtualFree(mappedMemoryData, 0, MEM_RELEASE);
    return true;
}
