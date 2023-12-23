#pragma once

#include "Utils.h"


typedef struct _PE_SECTION
{
	PIMAGE_SECTION_HEADER header;
	PVOID addrSection;
}PE_SECTION, * PPE_SECTION;

typedef struct _PE_STRUCT
{
	PVOID imageBase;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PVOID* dataDirectories;
	PPE_SECTION sections;

} PE_STRUCT, * PPE_STRUCT;

PPE_STRUCT createPEStrcut(PVOID peContent);
PPE_SECTION getSection(PPE_STRUCT myPE, PCHAR sectionName);
DWORD getOffsetFromAddr(PPE_STRUCT myPE, PVOID addr);