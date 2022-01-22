#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h> // WinAPI Header
#include <TlHelp32.h> //WinAPI Process API


// use this if you want to read the executable from disk
HANDLE MapFileToMemory(LPCSTR filename)
{
	FILE* file;
	file = fopen(filename, "rb");
	if (file != NULL)
	{
		fseek(file, 0, SEEK_END);
		long size = ftell(file);
		if (size < 0)
		{
			return NULL;
		}
		char* Memblock = malloc(size);
		if (Memblock == NULL)
		{
			return NULL;
		}
		fseek(file, 0, SEEK_SET);
		fread(Memblock, 1u, size, file);
		fclose(file);

		return Memblock;
	}
	else
	{
		return NULL;
	}
}

int RunPortableExecutable(void* Image)
{
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	CONTEXT* CTX;

	DWORD* ImageBase; //Base address of the image
	void* pImageBase; // Pointer to the image base

	int count;
	char CurrentFilePath[1024];

	DOSHeader = (PIMAGE_DOS_HEADER)(Image); // Initialize Variable
	NtHeader = (PIMAGE_NT_HEADERS)((DWORD)(Image) + DOSHeader->e_lfanew); // Initialize

	GetModuleFileNameA(0, CurrentFilePath, 1024); // path to current executable

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		ZeroMemory(&PI, sizeof(PI)); // Null the memory
		ZeroMemory(&SI, sizeof(SI)); // Null the memory

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
			CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) // Create a new instance of current
			//process in suspended state, for the new image.
		{
			// Allocate memory for the context.
			CTX = (LPCONTEXT)(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			if (CTX == NULL)
			{
				return 0;
			}
			CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

			if (GetThreadContext(PI.hThread, (LPCONTEXT)(CTX))) //if context is in thread
			{
				// Read instructions
				ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX->Ebx + 8), (LPVOID)(&ImageBase), 4, 0);

				pImageBase = VirtualAllocEx(PI.hProcess, (LPVOID)(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);
				if (pImageBase == NULL)
				{
					return 0;
				}

				// Write the image to the process
				WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)(Image) + DOSHeader->e_lfanew + 248 + (count * 40));
					
					WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)(pImageBase) + SectionHeader->VirtualAddress),
						(LPVOID)((DWORD)(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}
				WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Ebx + 8),
					(LPVOID)(&NtHeader->OptionalHeader.ImageBase), 4, 0);
				
				// Move address of entry point to the eax register
				CTX->Eax = (DWORD)(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, (LPCONTEXT)(CTX)); // Set the context
				ResumeThread(PI.hThread); //´Start the process/call main()

				return 1; // Operation was successful.
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
}

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		return EXIT_FAILURE;
	}
	const char* const exe = argv[1];
	printf("Running \"%s\".\n", exe);
	void* rawData = MapFileToMemory(exe);
	if (rawData == NULL)
	{
		return EXIT_FAILURE;
	}
	int code;
	if (RunPortableExecutable(rawData)) // run executable from the array
	{
		printf("\nSuccessfully ran \"%s\".\n", exe);
		code = EXIT_SUCCESS;
	}
	else
	{
		printf("\nFailed running \"%s\".\n", exe);
		code = EXIT_FAILURE;
	}
	free(rawData);
	return code;
}
