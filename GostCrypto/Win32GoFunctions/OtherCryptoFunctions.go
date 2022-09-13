package win32

import (
	"unsafe"
)

//CryptEnumProviders
//  [in]      DWORD  dwIndex, Index of the next provider to be enumerated.
//  [in]      DWORD  *pdwReserved =0,
//  [in]      DWORD  dwFlags =0,
//  [out]     DWORD  *pdwProvType,
//  [out]     LPWSTR szProvName,
//  [in, out] DWORD  *pcbProvName
func CryptEnumProviders(dwIndex uint32, pdwReserved *uint32, dwFlags uint32, pdwProvType *uint32, szProvName *byte, pcbProvName *uint32) (err error) {
	if r1, _, err := procCryptEnumProviders.Call(
		uintptr(dwIndex),
		uintptr(unsafe.Pointer(pdwReserved)),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(&pdwProvType)),
		uintptr(unsafe.Pointer(szProvName)),
		uintptr(unsafe.Pointer(pcbProvName)),
	); r1 == 0 {
		return err
	}
	return nil
}
