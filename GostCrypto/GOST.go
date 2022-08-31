package GostCrypto

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

func CreateHashFromData(hProvider windows.Handle, algID AlgorythmID, pbdata *byte, lendata uint32) (hashValue []byte, err error) {
	var hHash windows.Handle
	if err := CryptCreateHash(hProvider, algID, 0, &hHash); err != nil {
		return nil, err
	}
	if err := CryptHashData(hHash, pbdata, lendata); err != nil {
		return nil, err
	}
	hVal, err := CryptGetHashParam(hHash, HP_HASHVAL)
	if err != nil {
		return nil, err
	}
	return hVal, nil
}

// CryptCreateHash
//BOOL CryptCreateHash(
//[in]  HCRYPTPROV hProv,
//[in]  ALG_ID     Algid,
//[in]  HCRYPTKEY  hKey =0 TODO: check this for HMAC/MAC,
//[in]  DWORD      dwFlags,
//[out] HCRYPTHASH *phHash
func CryptCreateHash(hProvider windows.Handle, algID AlgorythmID, hKey int, hashHandle *windows.Handle) error {
	dwFlags := 0
	if r1, _, err := procCryptCreateHash.Call(
		uintptr(hProvider),
		uintptr(algID),
		uintptr(hKey),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(hashHandle))); r1 == 0 {
		return err
	}
	return nil
}

// CryptHashData
//BOOL CryptHashData(
//[in] HCRYPTHASH hHash,
//[in] const BYTE *pbData,
//[in] DWORD      dwDataLen,
//[in] DWORD      dwFlags
func CryptHashData(hHash windows.Handle, pbdata *byte, dwDataLen uint32) error {
	dwFlags := 0
	if r1, _, err := procCryptHashData.Call(
		uintptr(hHash),
		uintptr(unsafe.Pointer(pbdata)),
		uintptr(dwDataLen),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}

// CryptGetHashParam
//[in]      HCRYPTHASH hHash,
//[in]      DWORD      dwParam,
//[out]     BYTE       *pbData,
//[in, out] DWORD(uint32)      *pdwDataLen,
//[in]      DWORD      dwFlags
func CryptGetHashParam(hHash windows.Handle, dwParam uint32) (hashValue []byte, err error) {
	var pdwDatalen uint32
	//pbData1 := make([]byte, 256)
	dwFlags := 0
	if r1, _, err := procGetHashParam.Call(
		uintptr(hHash),
		uintptr(dwParam),
		uintptr(0),
		uintptr(unsafe.Pointer(&pdwDatalen)),
		uintptr(dwFlags)); r1 == 0 {
		return nil, err
	}
	pbData := make([]byte, pdwDatalen)
	if r1, _, err := procGetHashParam.Call(
		uintptr(hHash),
		uintptr(dwParam),
		uintptr(unsafe.Pointer(&pbData[0])),
		uintptr(unsafe.Pointer(&pdwDatalen)),
		uintptr(dwFlags)); r1 == 0 {
		return nil, err
	}
	return pbData, nil
}

// GetProviderParam
//[in]      HCRYPTPROV(windows.Handle) hProv,
//[in]      DWORD(uint32)      dwParam,
//[out]     BYTE(*byte)       *pbData,
//[in, out] DWORD(uint32)      *pdwDataLen,
//[in]      DWORD(uint32)      dwFlags
//TODO: rename to get provider name? oe needed other params?
func GetProviderParam(handleProvider windows.Handle) (param []byte, err error) {
	var pdwDtalen uint32
	//Получаем размер буфера для pbData
	if r1, _, err := procCryptGetProviderParam.Call(
		uintptr(handleProvider),
		uintptr(uint32(PP_NAME)),
		0,
		uintptr(unsafe.Pointer(&pdwDtalen)),
		0); r1 == 0 {
		return nil, err
	}
	//Создаем переменную для записи
	pbData := make([]byte, pdwDtalen)

	if r1, _, err := procCryptGetProviderParam.Call(
		uintptr(handleProvider),
		uintptr(uint32(PP_NAME)),
		uintptr(unsafe.Pointer(&pbData[0])),
		uintptr(unsafe.Pointer(&pdwDtalen)),
		0); r1 == 0 {
		return nil, err
	}
	return pbData, nil
}

// EnumProviders BOOL CryptEnumProvidersW(
//[in]      DWORD  dwIndex,
//[in]      DWORD  *pdwReserved,
//[in]      DWORD(uint32)  dwFlags,
//[out]     DWORD  *pdwProvType,
//[out]     LPWSTR szProvName,
//[in, out] DWORD  *pcbProvName
//);
func EnumProviders() (providers []*CryptoProvider, err error) {
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
	return providers, nil
}

//TODO: not implemented yet,there is not working stub
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
