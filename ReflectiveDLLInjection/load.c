#include "loadhead.h"
//==============================================================================================
//版权所有 (c) 2022, 天河GalaXY
//
//在满足以下条件的情况下，允许源代码和二进制形式进行重分发和使用，无论是否经过修改；
//
//	*重新发布源代码必须保留上述版本声明、本条件列表及以下免责声明。
// 
//	*以二进制形式发布的版本必须在发布版本提供的文档或其他材料中复制上述版权声明，本条件列表及以
//	下免责声明。
// 
//	*未经事先书面许可，安全公司或其贡献者的名字不得用于认可或推广由本软件衍生的产品
// 
// 软件提供者对于使用者及贡献者任何直接的、间接的、附带的、特殊的、相应损害不负任何责任
//==============================================================================================


//获取pe头基址
__int32 __stdcall GetNtBaseAddress_new(IN __int32 file_address) {
	return *(__int32*)(file_address + 0x3c) + file_address;
}
//检查pe文件正确性
BOOL __stdcall CheckPE(__int32 file_address) {
	__int32 flag_PE = *(__int32*)GetNtBaseAddress_new(file_address);
	if (flag_PE == 0x50450000) {
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
BOOL __stdcall CheckDllM(__int32 file_address) {
	__int16 flag_dll = *(__int16*)(GetNtBaseAddress_new(file_address) + 0x22);
	if (flag_dll == 0x210) {
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
BOOL __stdcall CheckEXEM(__int32 file_address) {
	__int16 flag_dll = *(__int16*)(GetNtBaseAddress_new(file_address) + 0x22);
	if (flag_dll == 0x010F) {
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
//获取拓展头大小
__int16 __stdcall GetOptionHeader_size(IN __int32 file_address) {
	/// <summary>
	/// 
	/// </summary>
	/// <param name="file_address"></param>
	/// <returns></returns>
	//printf("%d\n", GetNtBaseAddress_new(file_address));
	return *(__int16*)(GetNtBaseAddress_new(file_address) + 20);
}
//获取段表基址
__int32 __stdcall GetSectionTableAddress(IN __int32 file_address) {
	__int16 optionheader_size = GetOptionHeader_size(file_address);
	/// <summary>
	/// 
	/// </summary>
	/// <param name="file_address"></param>
	/// <returns></returns>
	//printf("%d", optionheader_size);
	__int32 NtBaseAddress = GetNtBaseAddress_new(file_address);
	return NtBaseAddress + 0x18 + optionheader_size;
}
//获取段表数目
__int16 __stdcall GetNumberOfSection(IN __int32 file_address) {
	return *(__int16*)(GetNtBaseAddress_new(file_address) + 0x6);
}
//返回0代表成功,-1错误
int __stdcall GetSectionAddressByName(IN __int32 file_address,
	IN char* section_name,
	OUT __int32* size_file,
	OUT __int32* size_mem,
	OUT __int32* RVA_file,
	OUT __int32* RVA_mem) {

	char* name;
	__int32 baseaddress = GetSectionTableAddress(file_address);

	int num = 0;
	for (__int32 i = 0; num < GetNumberOfSection(file_address); i = i + 0x28) {
		name = (char*)(baseaddress + i);

		if (!strcmp(name, section_name)) {
			*size_mem = *(int*)(baseaddress + i + 8);
			*RVA_mem = *(int*)(baseaddress + i + 12);
			*size_file = *(int*)(baseaddress + i + 16);
			*RVA_file = *(int*)(baseaddress + i + 20);
			return 0;
		}
		num++;
	}
	return -1;
}

//根据表序号查找段信息
//section_num下标从0开始
int __stdcall GetSectionAddressByNum(IN __int32 file_address,
	IN __int32 section_num,
	OUT __int32* size_file,
	OUT __int32* size_mem,
	OUT __int32* RVA_file,
	OUT __int32* RVA_mem) {

	__int32 num = 0;
	__int32 baseaddress = GetSectionTableAddress(file_address);
	for (__int32 i = 0; num < GetNumberOfSection(file_address); i = i + 0x28) {
		if (num == section_num) {
			*size_mem = *(int*)(baseaddress + i + 8);
			*RVA_mem = *(int*)(baseaddress + i + 12);
			*size_file = *(int*)(baseaddress + i + 16);
			*RVA_file = *(int*)(baseaddress + i + 20);
			return 0;
		}
		num++;
	}
	return -1;
}
__int32 __stdcall GetBaseAddress(__int32 file_address) {
	__int32 opbase = GetNtBaseAddress_new(file_address) + 0x18;
	return *(__int32*)(opbase + 28);
}

__int32 __stdcall LoadLibrary_my(__int32 file_address) {
	__int16 section_size = GetNumberOfSection(file_address);
	__int32* size_file = (int*)malloc(sizeof(__int32));
	__int32* size_mem = (int*)malloc(sizeof(__int32));
	__int32* rva_file = (int*)malloc(sizeof(__int32));
	__int32* rva_mem = (int*)malloc(sizeof(__int32));
	int sizeofmem = 0;
	for (int i = 0; i < section_size; i++) {
		GetSectionAddressByNum(file_address, i, size_file, size_mem, rva_file, rva_mem);
		sizeofmem = (*size_mem/0x1000 + 1)*0x1000 + sizeofmem;
	}
	sizeofmem = sizeofmem + 0x1000;


	//确定加载基址
	void* base_address = malloc(sizeofmem);

	//加载段
	for (int i = 0; i < section_size; i++) {
		GetSectionAddressByNum(file_address, i, size_file, size_mem, rva_file, rva_mem);
		//
		int base_section = file_address + *rva_file;
	
		for (int a = 0; a < *size_mem; a++) {
			//内存加载地址的指针内容=内存静态文件的内容

			*(BYTE*)((int)base_address + *rva_mem + a) = *(BYTE*)(base_section + a);
		}

		//加载多余用0填充
		for (int a = *size_mem; a/0x1000 < *size_mem/0x1000 + 1; a++) {
			*(BYTE*)((int)base_address + *rva_mem + a) = 0;
		}
	}
	//加载pe头
	GetSectionAddressByNum(file_address, 0, size_file, size_mem, rva_file, rva_mem);
	for (int i = 0; i < *rva_file; i++) {
		*(BYTE*)((int)base_address + i) = *(BYTE*)(file_address + i);
	}
	for (int i = *rva_file; i < 0x1000; i++) {
		*(BYTE*)((int)base_address + i) = 0;
	}

	//做基址重定向处理
	char name_section[] = ".reloc";
	GetSectionAddressByName(file_address, name_section, size_file, size_mem, rva_file, rva_mem);

	//重定位表地址

	__int32 address_reloc = *(__int32*)(*rva_mem + (int)base_address);

	__int32 size_reloc = *(__int32*)(*rva_mem + (int)base_address + 4);

	__int16 as_;
	
	__int32 address_rel;
	
	__int32 baseadd = GetBaseAddress(file_address);

	int k = 1;

	__int32 address_ac = *rva_mem + (int)base_address + 8;
	while (TRUE) {

		//两个重定位表
		
		for (int i = 0; i < (size_reloc - 8) / 2; i++) {
			//重定位的地址,通常type位为0x3000所以这里就简单减不进行过程验证
			//如果dlltype位需要更改则更改此处源码

			if (*(__int16*)(address_ac + 2 * i)==0) {

				break;
			}
			__int16 as_3000 = *(__int16*)(address_ac + 2 * i);




			as_ = as_3000 - 0x3000;
			
			address_rel = as_ + (__int32)base_address + address_reloc;
			*(__int32*)address_rel = *(__int32*)address_rel - baseadd + (__int32)base_address;

		}
		address_ac = address_ac + size_reloc;
		address_reloc = *(__int32*)(address_ac - 8);
		size_reloc = *(__int32*)(address_ac - 4);
		if (address_reloc == 0)
		{
			break;
		}
	}

	GetSectionAddressByName(file_address, ".text", size_file, size_mem, rva_file, rva_mem);
	__int32 a = 1;
	VirtualProtect((int)base_address + *rva_mem, ((int)(*rva_file / 0x1000 + 1) * 0x1000), PAGE_EXECUTE_READ, &a);

	return (__int32)base_address;

}




__int32 __stdcall GetExpTableAddress(IN VOID* baseaddress) {
	__int32 nthead_address = GetNtBaseAddress_new((__int32)baseaddress);
	return *(__int32*)(nthead_address + 0x18 + 0x60) + (int)baseaddress;
}
__int32 __stdcall GetExpTableSize(IN VOID* baseaddress) {
	__int32 nthead_address = GetNtBaseAddress_new((__int32)baseaddress);
	return *(__int32*)(nthead_address + 0x18 + 0x60 + 0x4);
}
//获取导出地址表地址
__int32 __stdcall GetEAT(IN VOID* baseaddress) {
	return *(__int32*)(GetExpTableAddress(baseaddress) + 0x18 + 0x4);
}
//获取导出名称表地址
__int32 __stdcall GetENT(IN VOID* baseaddress) {
	return *(__int32*)(GetExpTableAddress(baseaddress) + 0x20);
}
//获取导出序号表地址
__int32 __stdcall GetENUMT(IN VOID* baseaddress) {
	return *(__int32*)(GetExpTableAddress(baseaddress) + 0x24);
}
//获取ent内的数组大小
__int32 __stdcall GetENTSize(IN VOID* baseaddress) {
	return *(__int32*)(GetExpTableAddress(baseaddress) + 0x18);
}
VOID* __stdcall GetProcAddress_new(IN VOID* baseaddress, IN char* func_name) {
	printf("%x",(int)baseaddress);
	__int32* ent_address = (__int32*)(GetENT(baseaddress) + (INT32)baseaddress);
	__int16* entnum_address = (__int16*)(GetENUMT(baseaddress) + (INT32)baseaddress);
	__int32* eat_address = (__int32*)(GetEAT(baseaddress) + (INT32)baseaddress);
	for (__int32 i = 0; i < GetENTSize(baseaddress); i++)
	{

		char* entname = (char*)(*ent_address + (INT32)baseaddress);
		__int16 entnum = *entnum_address;
		printf("%s\n", entname);
		if (!strcmp(entname ,func_name))
		{
			return (VOID*)(*(__int32*)(eat_address + entnum)+(int)baseaddress);
		}
		ent_address++;
		entnum_address++;
	}

}