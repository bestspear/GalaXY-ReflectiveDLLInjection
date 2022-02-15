#pragma once
#pragma once
#include <windows.h>
#include <stdio.h>
#define F_API __declspec(dllexport)

#ifdef __cplusplus
extern "C" {
#endif
	F_API __int32 __stdcall GetNtBaseAddress_new(IN __int32 file_address);
	F_API __int16 __stdcall GetOptionHeader_size(IN __int32 file_address);
	F_API __int32 __stdcall GetSectionTableAddress(IN __int32 file_address);
	F_API __int16 __stdcall GetNumberOfSection(IN __int32 file_address);
	F_API int __stdcall GetSectionAddressByName(IN __int32 file_address,
		IN char* section_name,
		OUT __int32* size_file,
		OUT __int32* size_mem,
		OUT __int32* RVA_file,
		OUT __int32* RVA_mem);
	F_API int __stdcall GetSectionAddressByNum(IN __int32 file_address,
		IN __int32 section_num,
		OUT __int32* size_file,
		OUT __int32* size_mem,
		OUT __int32* RVA_file,
		OUT __int32* RVA_mem);
	F_API __int32 __stdcall GetBaseAddress(__int32 file_address);
	F_API __int32 __stdcall LoadLibrary_my(__int32 file_address);
	F_API __int32 __stdcall GetExpTableAddress(IN VOID* baseaddress);
	F_API __int32 __stdcall GetExpTableSize(IN VOID* baseaddress);
	F_API __int32 __stdcall GetEAT(IN VOID* baseaddress);
	F_API __int32 __stdcall GetENT(IN VOID* baseaddress);
	F_API __int32 __stdcall GetENUMT(IN VOID* baseaddress);
	F_API __int32 __stdcall GetENTSize(IN VOID* baseaddress);
	F_API VOID* __stdcall GetProcAddress_new(IN VOID* baseaddress, IN char* func_name);

#ifdef __cplusplus
}
#endif