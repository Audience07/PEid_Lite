#include "head.h"
int main() {

	printf("author:Xue_001\n\n");

	char *str = (char*)malloc(sizeof(char)*100);

	//ΪPEͷ�ṹ������ڴ�
	struct FileSign* pFileSign = malloc(sizeof(struct FileSign));
	


	printf("�������·��:");
	gets(str);


	//���ļ������仺����
	LPVOID FileBuffer = _OpenFile(str);
	if (!FileBuffer) {
		system("pause");
		return 0;
	}

	//�ͷ�·��ָ��
	free(str);
	str = NULL;

	//��ȡPEͷ����ѡPEͷ
	//���ؽڱ�����Ϊ�ڱ�ѭ����׼��
	if (!(_ReadData(FileBuffer, pFileSign))) {
		printf("���ǿ�ִ���ļ�\n");
		return 0;
	}


	//Ϊ�ڱ�ṹ������ڴ�
	struct SectionTable* pSectionTable = malloc(sizeof(struct SectionTable) * (pFileSign->NumberOfSection));
	//��ȡ�ڱ�����
	_ReadSectionTable(pSectionTable,pFileSign);

	//ѭ����ӡ����
	_OutputPEData(pFileSign,pSectionTable);



	//�ͷ��ڴ�
	free(pFileSign);
	free(pSectionTable);


}

