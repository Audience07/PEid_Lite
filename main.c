#include "head.h"
int main() {

	printf("author:Xue_001\n\n");

	char *str = (char*)malloc(sizeof(char)*100);

	//为PE头结构体分配内存
	struct FileSign* pFileSign = malloc(sizeof(struct FileSign));
	


	printf("输入程序路径:");
	gets(str);


	//打开文件，分配缓冲区
	LPVOID FileBuffer = _OpenFile(str);
	if (!FileBuffer) {
		system("pause");
		return 0;
	}

	//释放路径指针
	free(str);
	str = NULL;

	//读取PE头，可选PE头
	//返回节表数量为节表循环做准备
	if (!(_ReadData(FileBuffer, pFileSign))) {
		printf("不是可执行文件\n");
		return 0;
	}


	//为节表结构体分配内存
	struct SectionTable* pSectionTable = malloc(sizeof(struct SectionTable) * (pFileSign->NumberOfSection));
	//读取节表数据
	_ReadSectionTable(pSectionTable,pFileSign);

	//循环打印数据
	_OutputPEData(pFileSign,pSectionTable);



	//释放内存
	free(pFileSign);
	free(pSectionTable);


}

