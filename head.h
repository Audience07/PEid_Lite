#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>


size_t _ReadData(LPVOID FileBuffer, struct FileSign* FileSign);
LPVOID _OpenFile(const char* str);
void _ReadSectionTable(struct SectionTable* pSectionTable);
void _OutputPEData(struct FileSign*, struct SectionTable*);


//PE����ѡPEͷ
struct FileSign {
	//��λָ��
	LPVOID NTHeader;
	LPVOID PEHeader;
	LPVOID OptionalHeader;

	//PEͷ
	DWORD MZHeader;
	WORD Machine;
	WORD NumberOfSection;
	DWORD SizeOfOptionHeader;

	//��ѡPEͷ
	WORD Magic;
	DWORD EntryPoint;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
};


//�ڱ�
struct SectionTable {
	LPVOID Point;
	char name[9];
	DWORD VirtualSize;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointToRawData;
	DWORD Characteristics;
};



