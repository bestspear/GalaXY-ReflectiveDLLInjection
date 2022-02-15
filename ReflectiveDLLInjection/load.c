#include "loadhead.h"
//==============================================================================================
//��Ȩ���� (c) 2022, ���GalaXY
//
//��������������������£�����Դ����Ͷ�������ʽ�����طַ���ʹ�ã������Ƿ񾭹��޸ģ�
//
//	*���·���Դ������뱣�������汾�������������б���������������
// 
//	*�Զ�������ʽ�����İ汾�����ڷ����汾�ṩ���ĵ������������и���������Ȩ�������������б���
//	������������
// 
//	*δ������������ɣ���ȫ��˾���乱���ߵ����ֲ��������Ͽɻ��ƹ��ɱ���������Ĳ�Ʒ
// 
// ����ṩ�߶���ʹ���߼��������κ�ֱ�ӵġ���ӵġ������ġ�����ġ���Ӧ�𺦲����κ�����
//==============================================================================================


//��ȡpeͷ��ַ
__int32 __stdcall GetNtBaseAddress_new(IN __int32 file_address) {
	return *(__int32*)(file_address + 0x3c) + file_address;
}
//���pe�ļ���ȷ��
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
//��ȡ��չͷ��С
__int16 __stdcall GetOptionHeader_size(IN __int32 file_address) {
	/// <summary>
	/// 
	/// </summary>
	/// <param name="file_address"></param>
	/// <returns></returns>
	//printf("%d\n", GetNtBaseAddress_new(file_address));
	return *(__int16*)(GetNtBaseAddress_new(file_address) + 20);
}
//��ȡ�α��ַ
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
//��ȡ�α���Ŀ
__int16 __stdcall GetNumberOfSection(IN __int32 file_address) {
	return *(__int16*)(GetNtBaseAddress_new(file_address) + 0x6);
}
//����0����ɹ�,-1����
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

//���ݱ���Ų��Ҷ���Ϣ
//section_num�±��0��ʼ
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


	//ȷ�����ػ�ַ
	void* base_address = malloc(sizeofmem);

	//���ض�
	for (int i = 0; i < section_size; i++) {
		GetSectionAddressByNum(file_address, i, size_file, size_mem, rva_file, rva_mem);
		//
		int base_section = file_address + *rva_file;
	
		for (int a = 0; a < *size_mem; a++) {
			//�ڴ���ص�ַ��ָ������=�ڴ澲̬�ļ�������

			*(BYTE*)((int)base_address + *rva_mem + a) = *(BYTE*)(base_section + a);
		}

		//���ض�����0���
		for (int a = *size_mem; a/0x1000 < *size_mem/0x1000 + 1; a++) {
			*(BYTE*)((int)base_address + *rva_mem + a) = 0;
		}
	}
	//����peͷ
	GetSectionAddressByNum(file_address, 0, size_file, size_mem, rva_file, rva_mem);
	for (int i = 0; i < *rva_file; i++) {
		*(BYTE*)((int)base_address + i) = *(BYTE*)(file_address + i);
	}
	for (int i = *rva_file; i < 0x1000; i++) {
		*(BYTE*)((int)base_address + i) = 0;
	}

	//����ַ�ض�����
	char name_section[] = ".reloc";
	GetSectionAddressByName(file_address, name_section, size_file, size_mem, rva_file, rva_mem);

	//�ض�λ���ַ

	__int32 address_reloc = *(__int32*)(*rva_mem + (int)base_address);

	__int32 size_reloc = *(__int32*)(*rva_mem + (int)base_address + 4);

	__int16 as_;
	
	__int32 address_rel;
	
	__int32 baseadd = GetBaseAddress(file_address);

	int k = 1;

	__int32 address_ac = *rva_mem + (int)base_address + 8;
	while (TRUE) {

		//�����ض�λ��
		
		for (int i = 0; i < (size_reloc - 8) / 2; i++) {
			//�ض�λ�ĵ�ַ,ͨ��typeλΪ0x3000��������ͼ򵥼������й�����֤
			//���dlltypeλ��Ҫ��������Ĵ˴�Դ��

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
//��ȡ������ַ���ַ
__int32 __stdcall GetEAT(IN VOID* baseaddress) {
	return *(__int32*)(GetExpTableAddress(baseaddress) + 0x18 + 0x4);
}
//��ȡ�������Ʊ��ַ
__int32 __stdcall GetENT(IN VOID* baseaddress) {
	return *(__int32*)(GetExpTableAddress(baseaddress) + 0x20);
}
//��ȡ������ű��ַ
__int32 __stdcall GetENUMT(IN VOID* baseaddress) {
	return *(__int32*)(GetExpTableAddress(baseaddress) + 0x24);
}
//��ȡent�ڵ������С
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