package GostCrypto

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

// Package provides a cryptoapi  win32 functions(started with Crypt prefix), and high level function.High-Level
// must be used ,except scenario that they doesn't provide expected behavior

type GostCrypto struct {
	hProvider Handle
	hHash     Handle
}

func (gost *GostCrypto) GetPtrToProviderHandle() *Handle {
	return &gost.hProvider
}

func (gost *GostCrypto) GetPtrToHashHandle() *Handle {
	return &gost.hHash
}

//
// Init and provider parameters HIgh - Level function
//

//NewGostCrypto Initialisation function, get crypto provider context
func NewGostCrypto(providerType ProvType, flags CryptAcquireContextDWFlagsParams) *GostCrypto {
	var hProvider Handle
	if err := CryptAcquireContext(&hProvider, nil, nil, providerType, flags); err != nil {
		fmt.Println(err.Error())
	}
	return &GostCrypto{hProvider: hProvider}
}

//CreateHashFromData upper level function for creating hash for data
func (gost *GostCrypto) CreateHashFromData(algID AlgoID, pbData *byte, lenData uint32) (hashValue []byte, err error) {
	if err := gost.CryptCreateHash(algID, 0, &gost.hHash); err != nil {
		return nil, err
	}
	if err := gost.CryptHashData(pbData, lenData); err != nil {
		return nil, err
	}
	hVal, err := gost.CryptGetHashParam(HP_HASHVAL)
	if err != nil {
		return nil, err
	}
	//TODO: defer CryptReleaseHash?
	return hVal, nil
}

// GetProviderName GetProviderParam [based on]
//[in]      HCRYPTPROV(Handle) hProv,
//[in]      DWORD(uint32)      dwParam,
//[out]     BYTE(*byte)       *pbData,
//[in, out] DWORD(uint32)      *pdwDataLen,
//[in]      DWORD(uint32)      dwFlags
//TODO: rename to get provider name? oe needed other params?
func (gost *GostCrypto) GetProviderName() (param []byte, err error) {
	var pdwDataLen uint32
	//Получаем размер буфера для pbData
	if r1, _, err := procCryptGetProviderParam.Call(
		uintptr(gost.hProvider),
		uintptr(uint32(PP_NAME)),
		0,
		uintptr(unsafe.Pointer(&pdwDataLen)),
		0); r1 == 0 {
		return nil, err
	}
	//Создаем переменную для записи
	pbData := make([]byte, pdwDataLen)

	if r1, _, err := procCryptGetProviderParam.Call(
		uintptr(gost.hProvider),
		uintptr(uint32(PP_NAME)),
		uintptr(unsafe.Pointer(&pbData[0])),
		uintptr(unsafe.Pointer(&pdwDataLen)),
		0); r1 == 0 {
		return nil, err
	}
	return pbData, nil
}

// EnumProviders
//[in]      DWORD  dwIndex,
//[in]      DWORD  *pdwReserved,
//[in]      DWORD(uint32)  dwFlags,
//[out]     DWORD  *pdwProvType,
//[out]     LPWSTR szProvName,
//[in, out] DWORD  *pcbProvName
func (gost *GostCrypto) EnumProviders() (providers []*CryptoProvider, err error) {
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
				return providers, nil
			} else {
				return nil, err
			}
		}
		szProvName := make([]byte, pcbProvName)
		if r1, _, err = procCryptEnumProviders.Call(
			uintptr(dwIndex),
			uintptr(0),
			0,
			uintptr(unsafe.Pointer(&pdwProvType)),
			uintptr(unsafe.Pointer(&szProvName[0])),
			uintptr(unsafe.Pointer(&pcbProvName)),
		); r1 == 0 {
			return nil, err
		}
		providers = append(providers, &CryptoProvider{
			ProviderName: string(szProvName),
			ProviderType: pdwProvType,
		})
		dwIndex++
	}
}

// GetDefaultProvider BOOL CryptGetDefaultProviderW( //TODO: not implemented yet,there is not working stub
//[in]      DWORD  dwProvType,
//[in]      DWORD  *pdwReserved,
//[in]      DWORD  dwFlags,
//[out]     LPWSTR pszProvName,
//[in, out] DWORD  *pcbProvName
func (gost *GostCrypto) GetDefaultProvider() {
	result, name := "", ""
	ptr, _ := syscall.UTF16PtrFromString(result)
	ptrName, _ := syscall.UTF16PtrFromString(name)
	if r1, _, err := procCryptGetDefaultProvider.Call(
		uintptr(ProvGost2012),
		0,
		0x1,
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(ptrName)),
	); r1 == 0 {
		fmt.Println(err)
	}
	fmt.Println(&ptr, &ptrName)
}
