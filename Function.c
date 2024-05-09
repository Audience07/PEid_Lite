#include "head.h"

//���ļ������仺�����������ļ�������ָ��
LPVOID _OpenFile(IN const char* str) {
	FILE* pf = fopen(str, "rb");
	if (!pf) {
		perror("���ļ�ʧ��");
		return NULL;
	}
	//��ȡ�ļ���С
	fseek(pf, 0, SEEK_END);
	DWORD FileSize = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	//�����ڴ�
	LPVOID FileBuffer = (char*)malloc(FileSize);
	if (!FileBuffer) {
		printf("�ڴ����ʧ��\n");
		fclose(pf);
		return NULL;
	}

	//���ڴ��ȡ��������
	fread(FileBuffer, 1, FileSize, pf);
	if (!FileBuffer) {
		printf("��ȡ�ڴ�ʧ��\n");
		free(FileBuffer);
		fclose(pf);
		return NULL;
	}
	fclose(pf);
	return FileBuffer;

}



//��ȡ�ļ���ʶ���洢��FileSign�ṹ�У����ؽڱ�����
size_t _ReadData(IN LPVOID FileBuffer, OUT struct FileSign* FileSign) {
	FileSign->MZHeader = *(WORD*)((char*)FileBuffer);
	if (FileSign->MZHeader != 0x5a4d) {
		return 0;
	}
	//ƫ��ָ��
	FileSign->NTHeader = (char*)((char*)FileBuffer + (*(DWORD*)((char*)FileBuffer + 0x3C)));
	FileSign->PEHeader = (char*)((char*)FileSign->NTHeader + 0x4);
	FileSign->OptionalHeader = (char*)((char*)FileSign->NTHeader + 0x18);

	//PEͷ
	FileSign->Machine = *(WORD*)((char*)FileSign->PEHeader);
	FileSign->NumberOfSection = *(WORD*)((char*)FileSign->PEHeader + 0x2);
	FileSign->SizeOfOptionHeader = *(WORD*)((char*)FileSign->PEHeader + 0x10);

	//��ѡPEͷ
	FileSign->Magic = *(WORD*)((char*)FileSign->OptionalHeader);
	FileSign->EntryPoint = *(DWORD*)((char*)FileSign->OptionalHeader + 0x10);
	FileSign->ImageBase = *(DWORD*)((char*)FileSign->OptionalHeader + 0x1C);
	FileSign->SectionAlignment = *(DWORD*)((char*)FileSign->OptionalHeader + 0x20);
	FileSign->FileAlignment = *(DWORD*)((char*)FileSign->OptionalHeader + 0x24);
	FileSign->SizeOfImage = *(DWORD*)((char*)FileSign->OptionalHeader + 0x38);
	FileSign->SizeOfHeaders = *(DWORD*)((char*)FileSign->OptionalHeader + 0x3C);

	//���ؽڱ�����
	return 1;
}

//��ȡ�ڱ�ؼ��ֶ�
void _ReadSectionTable(OUT struct SectionTable* pSectionTable, IN struct FileSign* pFileSign) {
	for (int i = 0; i < pFileSign->NumberOfSection;i++, pSectionTable++) {
		pSectionTable->Point = (char*)((char*)pFileSign->OptionalHeader + pFileSign->SizeOfOptionHeader+(i*0x28));
		memcpy(pSectionTable->name, pSectionTable->Point, 8);
		pSectionTable->VirtualSize = *(DWORD*)((char*)pSectionTable->Point + 0x8);
		pSectionTable->VirtualAddress = *(DWORD*)((char*)pSectionTable->Point + 0xC);
		pSectionTable->SizeOfRawData = *(DWORD*)((char*)pSectionTable->Point + 0x10);
		pSectionTable->PointToRawData = *(DWORD*)((char*)pSectionTable->Point + 0x14);
		pSectionTable->Characteristics = *(DWORD*)((char*)pSectionTable->Point + 0x24);
	}
}

//���PE�ṹ�ؼ��ֶ�
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable) {
	printf("**********************************************************\n");
	printf("PEͷ:\n\n");
	//���PEͷ
	printf("Machine:0x%x\n", pFileSign->Machine);
	printf("NumberOfSection:0x%x\n", pFileSign->NumberOfSection);
	printf("SizeOfOptionHeader:0x%x\n\n", pFileSign->SizeOfOptionHeader);

	//�����ѡPEͷ
	printf("��ѡPEͷ:\n\n");
	printf("Magic:0x%x\n", pFileSign->Magic);
	printf("EntryPoint:0x%x\n", pFileSign->EntryPoint);
	printf("ImageBase:0x%x\n", pFileSign->ImageBase);
	printf("SectionAlignment:0x%x\n", pFileSign->SectionAlignment);
	printf("FileAlignment:0x%x\n", pFileSign->FileAlignment);
	printf("SizeOfImage:0x%x\n", pFileSign->SizeOfImage);
	printf("SizeOfHeaders:0x%x\n\n", pFileSign->SizeOfHeaders);

	printf("�ڱ�:\n\n");
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		printf("name:%s\n", pSectionTable->name);
		printf("VirtualSize:0x%x\n", pSectionTable->VirtualSize);
		printf("VirtualAddress:0x%x\n", pSectionTable->VirtualAddress);
		printf("SizeOfRawData:0x%x\n", pSectionTable->SizeOfRawData);
		printf("PointToRawData:0x%x\n", pSectionTable->PointToRawData);
		printf("Characteristics:0x%x\n\n", pSectionTable->Characteristics);
		pSectionTable++;
	}
	printf("**********************************************************\n");
	system("pause");
}