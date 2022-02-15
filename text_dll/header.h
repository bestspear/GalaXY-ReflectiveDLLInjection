#pragma once
#define F_API __declspec(dllexport)
#ifdef __cplusplus
extern "C" {
#endif

	F_API int __stdcall add(int a, int b);
	F_API int __stdcall sub(int a, int b);
	F_API int __stdcall mult(int a, int b);

#ifdef __cplusplus
}
#endif // 
