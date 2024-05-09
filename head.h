#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>


//打开文件并分配缓冲区，返回文件缓冲区指针
LPVOID _OpenFile(IN const char* str);
//读取数据，失败返回0,成功返回1
size_t _ReadData(IN LPVOID FileBuffer, OUT struct FileSign* FileSign);
//读取节表数据，存储到pSectionTable结构体中
void _ReadSectionTable(OUT struct SectionTable* pSectionTable, IN struct FileSign* pFileSign);
//输出读取的内容
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);


//PE，可选PE头
struct FileSign {
	//定位指针
	LPVOID NTHeader;
	LPVOID PEHeader;
	LPVOID OptionalHeader;

	//PE头
	DWORD MZHeader;
	WORD Machine;
	WORD NumberOfSection;
	DWORD SizeOfOptionHeader;

	//可选PE头
	WORD Magic;
	DWORD EntryPoint;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
};


//节表
struct SectionTable {
	LPVOID Point;
	char name[9];
	DWORD VirtualSize;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointToRawData;
	DWORD Characteristics;
};



