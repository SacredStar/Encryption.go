package GostCrypto

import "C"
import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

// CryptCreateHash
//BOOL CryptCreateHash(
//[in]  HCRYPTPROV hProv,
//[in]  ALG_ID     Algid(uint32),
//[in]  HCRYPTKEY  hKey =0 TODO: check this for HMAC/MAC,
//[in]  DWORD      dwFlags,
//[out] HCRYPTHASH *phHash
func CryptCreateHash(handleProvider windows.Handle, algID AlgorythmID) (hashHandle windows.Handle) {
	
}

// GetProviderParam
//[in]      HCRYPTPROV(windows.Handle) hProv,
//[in]      WORD(uint32)      dwParam,
//[out]     BYTE(*byte)       *pbData,
//[in, out] WORD(uint32)      *pdwDataLen,
//[in]      WORD(uint32)      dwFlags
func GetProviderParam(handleProvider windows.Handle) {
	var pdwDtalen uint32
	//Получаем размер буфера для pbData
	r1, _, err := procCryptGetProviderParam.Call(
		uintptr(handleProvider),
		uintptr(uint32(PP_NAME)),
		0,
		uintptr(unsafe.Pointer(&pdwDtalen)),
		0)
	//TODO: refactor this
	if r1 != 1 {
		print(r1, err.Error())
		return
	}
	//Создаем переменную для записи
	pbData := make([]byte, pdwDtalen)

	r1, _, err = procCryptGetProviderParam.Call(
		uintptr(handleProvider),
		uintptr(uint32(PP_NAME)),
		uintptr(unsafe.Pointer(&pbData[0])),
		uintptr(unsafe.Pointer(&pdwDtalen)),
		0)
	//TODO: refactor this
	if r1 != 1 {
		print(r1, err.Error())
		return
	}
	//TODO: set as return value
	fmt.Println(pdwDtalen, string(pbData))

}

// EnumProviders BOOL CryptEnumProvidersW(
//[in]      DWORD  dwIndex,
//[in]      DWORD  *pdwReserved,
//[in]      DWORD(uint32)  dwFlags,
//[out]     DWORD  *pdwProvType,
//[out]     LPWSTR szProvName,
//[in, out] DWORD  *pcbProvName
//);
func EnumProviders() (providers []*CryptoProvider) {
	var dwIndex, pdwProvType, pcbProvName uint32

	dwIndex = 0
	for {
		r1, _, err := procCryptEnumProviders.Call(
			uintptr(dwIndex),
			uintptr(0),
			0,
			uintptr(unsafe.Pointer(&pdwProvType)),
			0,
			uintptr(unsafe.Pointer(&pcbProvName)),
		)
		if r1 == 0 {
			if err == windows.ERROR_NO_MORE_ITEMS {
				return providers
			} else {
				fmt.Println("Ошибка", err.Error())
			}
		}
		szProvName := make([]byte, pcbProvName)
		r1, _, err = procCryptEnumProviders.Call(
			uintptr(dwIndex),
			uintptr(0),
			0,
			uintptr(unsafe.Pointer(&pdwProvType)),
			uintptr(unsafe.Pointer(&szProvName[0])),
			uintptr(unsafe.Pointer(&pcbProvName)),
		)
		if r1 == 0 {
			fmt.Println("Ошибка2", err.Error())
			break
		}
		providers = append(providers, &CryptoProvider{
			ProviderName: string(szProvName),
			ProviderType: pdwProvType,
		})
		dwIndex++
	}
	return providers
}

//TODO: not implemented yet
// GetDefaultProvider BOOL CryptGetDefaultProviderW(
//[in]      DWORD  dwProvType,
//[in]      DWORD  *pdwReserved,
//[in]      DWORD  dwFlags,
//[out]     LPWSTR pszProvName,
//[in, out] DWORD  *pcbProvName
//);
func GetDefaultProvider() {
	result, name := "", ""
	ptr, _ := syscall.UTF16PtrFromString(result)
	ptrName, _ := syscall.UTF16PtrFromString(name)
	procCryptGetDefaultProvider.Call(
		uintptr(ProvGost2012),
		0,
		0x1,
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(ptrName)),
	)
	fmt.Println(&ptr, &ptrName)
}
