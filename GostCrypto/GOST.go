package GostCrypto

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

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

//NewGostCrypto Initialisation function
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

// CryptAcquireContext
//[out] HCRYPTPROV *phProv,
//[in]  LPCWSTR    szContainer,
//[in]  LPCWSTR    szProvider,
//[in]  DWORD      dwProvType,
//[in]  DWORD      dwFlags
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

// CryptCreateHash
//BOOL CryptCreateHash(
//[in]  HCRYPTPROV hProv,
//[in]  ALG_ID     Algid,
//[in]  HCRYPTKEY  hKey =0 TODO: check this for HMAC/MAC,
//[in]  DWORD      dwFlags,
//[out] HCRYPTHASH *phHash
func (gost *GostCrypto) CryptCreateHash(algID AlgoID, hKey int, hashHandle *Handle) error {
	dwFlags := 0
	if r1, _, err := procCryptCreateHash.Call(
		uintptr(gost.hProvider),
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
//[in] BYTE *pbData,
//[in] DWORD      dwDataLen,
//[in] DWORD      dwFlags
func (gost *GostCrypto) CryptHashData(pbData *byte, dwDataLen uint32) error {
	dwFlags := 0
	if r1, _, err := procCryptHashData.Call(
		uintptr(gost.hHash),
		uintptr(unsafe.Pointer(pbData)),
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
func (gost *GostCrypto) CryptGetHashParam(dwParam dwParam) (hashValue []byte, err error) {
	var pdwDataLen uint32
	//pbData1 := make([]byte, 256)
	dwFlags := 0
	if r1, _, err := procGetHashParam.Call(
		uintptr(gost.hHash),
		uintptr(dwParam),
		uintptr(0),
		uintptr(unsafe.Pointer(&pdwDataLen)),
		uintptr(dwFlags)); r1 == 0 {
		return nil, err
	}
	pbData := make([]byte, pdwDataLen)
	if r1, _, err := procGetHashParam.Call(
		uintptr(gost.hHash),
		uintptr(dwParam),
		uintptr(unsafe.Pointer(&pbData[0])),
		uintptr(unsafe.Pointer(&pdwDataLen)),
		uintptr(dwFlags)); r1 == 0 {
		return nil, err
	}
	return pbData, nil
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

//CryptGenRandom
//[in]      HCRYPTPROV hProv,
//[in]      DWORD      dwLen,
//[in, out] BYTE       *pbBuffer
func (gost *GostCrypto) CryptGenRandom(hProvider Handle, dwLenBytes uint32) (random []byte, err error) {
	rnd := make([]byte, dwLenBytes)
	if r1, _, err := procCryptGenRandom.Call(
		uintptr(hProvider),
		uintptr(dwLenBytes),
		uintptr(unsafe.Pointer(&rnd[0])),
	); r1 == 0 {
		return nil, err
	}
	return rnd, nil
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
