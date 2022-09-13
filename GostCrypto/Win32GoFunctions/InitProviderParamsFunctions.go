package win32

import "unsafe"

// CryptAcquireContext
//  [out] HCRYPTPROV *phProv,
//  [in]  LPCWSTR    szContainer,
//  [in]  LPCWSTR    szProvider,
//  [in]  DWORD      dwProvType,
//  [in]  DWORD      dwFlags
func CryptAcquireContext(provHandle *Handle, container *uint16, provider *uint16, provType ProvType, flags CryptAcquireContextDWFlagsParams) (err error) {
	if r1, _, err := procCryptAcquireContext.Call(
		uintptr(unsafe.Pointer(provHandle)),
		uintptr(unsafe.Pointer(container)),
		uintptr(unsafe.Pointer(provider)),
		uintptr(provType),
		uintptr(flags)); r1 == 0 {
		return err
	}
	return nil
}

// CryptReleaseContext
//  [in] HCRYPTPROV hProv,
//  [in] DWORD      dwFlags = 0 ( dwFlags not used for now, stub for future in CSP
func CryptReleaseContext(provHandle Handle) (err error) {
	if r1, _, err := procCryptReleaseContext.Call(
		uintptr(provHandle),
		uintptr(0)); r1 == 0 {
		return err
	}
	return nil
}

// CryptSetProvParam
//  [in] HCRYPTPROV hProv,
//  [in] DWORD      dwParam,
//  [in] const BYTE *pbData,
//  [in] DWORD      dwFlags
func CryptSetProvParam(provHandle Handle, dwParam GetSetProviderParams, pbData *byte, dwFlags uint32) (err error) {
	if r1, _, err := procCryptSetProviderParam.Call(
		uintptr(provHandle),
		uintptr(dwParam),
		uintptr(unsafe.Pointer(pbData)),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}

//CryptGetProvParam
//  [in]      HCRYPTPROV hProv,
//  [in]      DWORD      dwParam,
//  [out]     BYTE       *pbData,
//  [in, out] DWORD      *pdwDataLen,
//  [in]      DWORD      dwFlags
func CryptGetProvParam(provHandle Handle, dwParam GetSetProviderParams, pbData *byte, pdwDataLen *uint32, dwFlags uint32) (err error) {
	if r1, _, err := procCryptGetProviderParam.Call(
		uintptr(provHandle),
		uintptr(dwParam),
		uintptr(unsafe.Pointer(pbData)),
		uintptr(unsafe.Pointer(pdwDataLen)),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}
