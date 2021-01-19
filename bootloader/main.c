#include <efi.h>
#include <efilib.h>
#include <elf.h>

#include <stdint.h>
#include <stddef.h>

typedef struct
{
	void* BaseAddress;

	size_t BufferSize;

	unsigned int Width;
	unsigned int Height;
	unsigned int PixelsPerScanLine;
} Framebuffer;

#define PSF1_MAGIC0 0x36
#define PSF1_MAGIC1 0x04

typedef struct
{
	unsigned char Magic[2];
	unsigned char mode;
	unsigned char CharacterSize;
} PSF1_HEADER;

typedef struct
{
	PSF1_HEADER* PSF1header;

	void* GlyphBuffer;
} PSF1_FONT;

Framebuffer framebuffer;

Framebuffer* InitializeGOP()
{
	EFI_GUID GOPguid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;

	EFI_GRAPHICS_OUTPUT_PROTOCOL* GOP;

	EFI_STATUS Status;

	Status = uefi_call_wrapper(BS->LocateProtocol, 3, &GOPguid, NULL, (void**)&GOP);

	if(EFI_ERROR(Status))
	{
		Print(L"Unable to find GOP!\n\r");
		return NULL;
	}
	else
	{
		Print(L"");
	}

	framebuffer.BaseAddress = (void*)GOP->Mode->FrameBufferBase;
	framebuffer.BufferSize = GOP->Mode->FrameBufferSize;

	framebuffer.Width = GOP->Mode->Info->HorizontalResolution;
	framebuffer.Height = GOP->Mode->Info->VerticalResolution;

	framebuffer.PixelsPerScanLine = GOP->Mode->Info->PixelsPerScanLine;

	return &framebuffer;
}

EFI_FILE* LoadFile(EFI_FILE* Directory, CHAR16* Path, EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
	EFI_FILE* LoadedFile;

	EFI_LOADED_IMAGE_PROTOCOL* LoadedImage;
	SystemTable->BootServices->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (void**)&LoadedImage);

	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* FileSystem;
	SystemTable->BootServices->HandleProtocol(LoadedImage->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (void**)&FileSystem);

	if (Directory == NULL)
	{
		FileSystem->OpenVolume(FileSystem, &Directory);
	}

	EFI_STATUS s = Directory->Open(Directory, &LoadedFile, Path, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);

	if (s != EFI_SUCCESS)
	{
		return NULL;
	}

	return LoadedFile;
}

PSF1_FONT* LoadPSF1Font(EFI_FILE* Directory, CHAR16* Path, EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
	EFI_FILE* Font = LoadFile(Directory, Path, ImageHandle, SystemTable);

	if (Font == NULL) return NULL;

	PSF1_HEADER* FontHeader;
	SystemTable->BootServices->AllocatePool(EfiLoaderData, sizeof(PSF1_HEADER), (void**)&FontHeader);

	UINTN size = sizeof(PSF1_HEADER);

	Font->Read(Font, &size, FontHeader);

	if (FontHeader->Magic[0] != PSF1_MAGIC0 || FontHeader->Magic[1] != PSF1_MAGIC1)
	{
		return NULL;
	}

	UINTN GlyphBufferSize = FontHeader->CharacterSize * 256;

	if (FontHeader->mode == 1)
	{
		GlyphBufferSize = FontHeader->CharacterSize * 512;
	}

	void* glyphBuffer;
	{
		Font->SetPosition(Font, sizeof(PSF1_HEADER));
		SystemTable->BootServices->AllocatePool(EfiLoaderData, GlyphBufferSize, (void**)&glyphBuffer);
		Font->Read(Font, &GlyphBufferSize, glyphBuffer);
	}

	PSF1_FONT* finishedFont;
	SystemTable->BootServices->AllocatePool(EfiLoaderData, sizeof(PSF1_FONT), (void**)&finishedFont);

	finishedFont->PSF1header = FontHeader;
	finishedFont->GlyphBuffer = glyphBuffer;

	return finishedFont;

}

int memcmp(const void* aptr, const void* bptr, size_t n)
{
	const unsigned char* a = aptr, *b = bptr;

	for (size_t i = 0; i < n; i++)
	{
		if (a[i] < b[i]) return -1;
		else if (a[i] > b[i]) return 1;
	}

	return 0;
}

EFI_STATUS efi_main (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
	InitializeLib(ImageHandle, SystemTable);

	EFI_FILE* Kernel = LoadFile(NULL, L"kernel.elf", ImageHandle, SystemTable);

	if (Kernel == NULL)
	{
		Print(L"Could not load kernel!\n\r");
	}
	else
	{
		Print(L"");
	}

	Elf64_Ehdr Header;
	{
		UINTN FileInfoSize;
	
		EFI_FILE_INFO* FileInfo;
	
		Kernel->GetInfo(Kernel, &gEfiFileInfoGuid, &FileInfoSize, NULL);
	
		SystemTable->BootServices->AllocatePool(EfiLoaderData, FileInfoSize, (void**)&FileInfo);
	
		Kernel->GetInfo(Kernel, &gEfiFileInfoGuid, &FileInfoSize, (void**)&FileInfo);

		UINTN size = sizeof(Header);
		Kernel->Read(Kernel, &size, &Header);
	}

	if
	(
		memcmp(&Header.e_ident[EI_MAG0], ELFMAG, SELFMAG) != 0 ||
		Header.e_ident[EI_CLASS] != ELFCLASS64 ||
		Header.e_ident[EI_DATA] != ELFDATA2LSB ||
		Header.e_type != ET_EXEC ||
		Header.e_machine != EM_X86_64 ||
		Header.e_version != EV_CURRENT
	)
	{
		Print(L"Kernel format is bad!\r\n");
	}
	else
	{
		Print(L"");
	}

	Elf64_Phdr* phdrs;
	{
		Kernel->SetPosition(Kernel, Header.e_phoff);

		UINTN size = Header.e_phnum * Header.e_phentsize;

		SystemTable->BootServices->AllocatePool(EfiLoaderData, size, (void**)&phdrs);
		Kernel->Read(Kernel, &size, phdrs);
	}

	for
	(
		Elf64_Phdr* phdr = phdrs;
		(char*)phdr < (char*)phdrs + Header.e_phnum * Header.e_phentsize;
		phdr = (Elf64_Phdr*)((char*)phdr + Header.e_phentsize)
	)
	{
		switch (phdr->p_type)
		{
			case PT_LOAD:
			{
				int pages = (phdr->p_memsz + 0x1000 - 1) / 0x1000;

				Elf64_Addr segment = phdr->p_paddr;
				SystemTable->BootServices->AllocatePages(AllocateAddress, EfiLoaderData, pages, &segment);

				Kernel->SetPosition(Kernel, phdr->p_offset);

				UINTN size = phdr->p_filesz;

				Kernel->Read(Kernel, &size, (void*)segment);

				break;
			}
		}
	}

	Print(L"Kernel Loaded!\n\r");
	
	void (*KernelStart)(Framebuffer*, PSF1_FONT*) = ((__attribute__((sysv_abi)) void (*)(Framebuffer*, PSF1_FONT*) ) Header.e_entry);

	PSF1_FONT* newFont = LoadPSF1Font(NULL, L"zap-light16.psf", ImageHandle, SystemTable);

	if (newFont == NULL)
	{
		Print(L"Font is not valid or is not found!\n\r");
	}
	else
	{
		Print(L"");
	}

	Framebuffer* newBuffer = InitializeGOP();

	KernelStart(newBuffer, newFont);

	return EFI_SUCCESS;
}
