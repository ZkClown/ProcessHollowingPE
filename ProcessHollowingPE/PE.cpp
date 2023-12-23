#include "PE.h"

PPE_STRUCT createPEStrcut(PVOID peContent) 
{
	PPE_STRUCT myStruct = (PPE_STRUCT)LocalAlloc(LPTR, sizeof(PE_STRUCT));
	if (!myStruct) {
		return nullptr;
	}

	myStruct->imageBase = peContent;
	myStruct->dosHeader = (PIMAGE_DOS_HEADER)peContent;

	if (myStruct->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		_err("[-] ERROR: Input file seems to not be a PE\r\n");
		LocalFree(myStruct);
		return nullptr;
	}

	myStruct->ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)peContent + myStruct->dosHeader->e_lfanew);

	myStruct->dataDirectories = (PVOID*)LocalAlloc(LPTR, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(PVOID));

	if (!myStruct->dataDirectories) {

		_err("[-] ERROR: in allocating memory for data directories\r\n");
		LocalFree(myStruct);
		return nullptr;
	}

	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
		myStruct->dataDirectories[i] = myStruct->ntHeader->OptionalHeader.DataDirectory[i].VirtualAddress + (PBYTE)peContent;
	}

	myStruct->sections = (PPE_SECTION)LocalAlloc(LPTR, myStruct->ntHeader->FileHeader.NumberOfSections * sizeof(PE_SECTION));

	if (!myStruct->sections) {

		_err("[-] ERROR: in allocating memory for sections\r\n");

		LocalFree(myStruct->dataDirectories);
		LocalFree(myStruct);
		return nullptr;
	}

	PIMAGE_SECTION_HEADER currentPeSection = IMAGE_FIRST_SECTION(myStruct->ntHeader);

	for (int i = 0; i < myStruct->ntHeader->FileHeader.NumberOfSections; i++) {
		myStruct->sections[i].header = currentPeSection;
		myStruct->sections[i].addrSection = (PBYTE)peContent + currentPeSection->PointerToRawData;
		currentPeSection++;
	}

	return myStruct;
}

PPE_SECTION getSection(PPE_STRUCT myPE, PCHAR sectionName)
{
	for (int i = 0; i < myPE->ntHeader->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((PCHAR)myPE->sections[i].header->Name, sectionName) == 0)
			return &myPE->sections[i];
	}
	return nullptr;
}

DWORD getOffsetFromAddr(PPE_STRUCT myPE, PVOID addr)
{
	DWORD calculatedOffset = (DWORD)addr - (DWORD)myPE->imageBase;
	for (int i = 0; i < myPE->ntHeader->FileHeader.NumberOfSections; i++)
	{
		_dbg("Addr: %p -> calculate offset: %x\r\n", addr, (DWORD)addr - (DWORD)myPE->imageBase);
		_dbg("Section: %s -> %x - %x\r\n", myPE->sections[i].header->Name, myPE->sections[i].header->VirtualAddress, myPE->sections[i].header->VirtualAddress + myPE->sections[i].header->SizeOfRawData);

		if (calculatedOffset > myPE->sections[i].header->VirtualAddress && calculatedOffset < myPE->sections[i].header->VirtualAddress + myPE->sections[i].header->SizeOfRawData)
		{
			_dbg("Offset found in section %s. Offset of section: %d\r\n", myPE->sections[i].header->Name, myPE->sections[i].header->VirtualAddress - myPE->sections[i].header->PointerToRawData);
			return myPE->sections[i].header->VirtualAddress - myPE->sections[i].header->PointerToRawData;
		}
	}
	return -1;
}