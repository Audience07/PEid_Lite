#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>


//���ļ������仺�����������ļ�������ָ��
LPVOID _OpenFile(IN const char* str);
//��ȡ���ݣ�ʧ�ܷ���0,�ɹ�����1
size_t _ReadData(IN LPVOID FileBuffer, OUT struct FileSign* FileSign);
//��ȡ�ڱ����ݣ��洢��pSectionTable�ṹ����
void _ReadSectionTable(OUT struct SectionTable* pSectionTable, IN struct FileSign* pFileSign);
//�����ȡ������
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);


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



