package GostCrypto

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

type GostCrypto struct {
	hProvider windows.Handle
	hHash     windows.Handle
}

func (gost *GostCrypto) GetPtrToProviderHandle() *windows.Handle {
	return &gost.hProvider
}

func (gost *GostCrypto) GetPtrToHashHandle() *windows.Handle {
	return &gost.hHash
}

//NewGostCrypto Initialisation function
func NewGostCrypto(providerType uint32, flags uint32) *GostCrypto {
	var hProvider windows.Handle
	if err := windows.CryptAcquireContext(&hProvider, nil, nil, providerType, flags); err != nil {
		fmt.Println(err.Error())
	}
	return &GostCrypto{hProvider: hProvider}
}

//CreateHashFromData upper level function for creating hash for data
func (gost *GostCrypto) CreateHashFromData(algID AlgorythmID, pbdata *byte, lendata uint32) (hashValue []byte, err error) {
	if err := gost.CryptCreateHash(algID, 0, &gost.hHash); err != nil {
		return nil, err
	}
	if err := gost.CryptHashData(pbdata, lendata); err != nil {
		return nil, err
	}
	hVal, err := gost.CryptGetHashParam(HP_HASHVAL)
	if err != nil {
		return nil, err
	}
	//TODO: defer CryptReleaseHash?
	return hVal, nil
}

// CryptCreateHash
//BOOL CryptCreateHash(
//[in]  HCRYPTPROV hProv,
//[in]  ALG_ID     Algid,
//[in]  HCRYPTKEY  hKey =0 TODO: check this for HMAC/MAC,
//[in]  DWORD      dwFlags,
//[out] HCRYPTHASH *phHash
func (gost *GostCrypto) CryptCreateHash(algID AlgorythmID, hKey int, hashHandle *windows.Handle) error {
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
func (gost *GostCrypto) CryptHashData(pbdata *byte, dwDataLen uint32) error {
	dwFlags := 0
	if r1, _, err := procCryptHashData.Call(
		uintptr(gost.hHash),
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
func (gost *GostCrypto) CryptGetHashParam(dwParam uint32) (hashValue []byte, err error) {
	var pdwDatalen uint32
	//pbData1 := make([]byte, 256)
	dwFlags := 0
	if r1, _, err := procGetHashParam.Call(
		uintptr(gost.hHash),
		uintptr(dwParam),
		uintptr(0),
		uintptr(unsafe.Pointer(&pdwDatalen)),
		uintptr(dwFlags)); r1 == 0 {
		return nil, err
	}
	pbData := make([]byte, pdwDatalen)
	if r1, _, err := procGetHashParam.Call(
		uintptr(gost.hHash),
		uintptr(dwParam),
		uintptr(unsafe.Pointer(&pbData[0])),
		uintptr(unsafe.Pointer(&pdwDatalen)),
		uintptr(dwFlags)); r1 == 0 {
		return nil, err
	}
	return pbData, nil
}

// GetProviderParam [based on]
//[in]      HCRYPTPROV(windows.Handle) hProv,
//[in]      DWORD(uint32)      dwParam,
//[out]     BYTE(*byte)       *pbData,
//[in, out] DWORD(uint32)      *pdwDataLen,
//[in]      DWORD(uint32)      dwFlags
//TODO: rename to get provider name? oe needed other params?
func (gost *GostCrypto) GetProviderName() (param []byte, err error) {
	var pdwDtalen uint32
	//Получаем размер буфера для pbData
	if r1, _, err := procCryptGetProviderParam.Call(
		uintptr(gost.hProvider),
		uintptr(uint32(PP_NAME)),
		0,
		uintptr(unsafe.Pointer(&pdwDtalen)),
		0); r1 == 0 {
		return nil, err
	}
	//Создаем переменную для записи
	pbData := make([]byte, pdwDtalen)

	if r1, _, err := procCryptGetProviderParam.Call(
		uintptr(gost.hProvider),
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
	return providers, nil
}

//BOOL CryptGenRandom(
//[in]      HCRYPTPROV hProv,
//[in]      DWORD      dwLen,
//[in, out] BYTE       *pbBuffer
func (gost *GostCrypto) CryptGenRandom(hProvider windows.Handle, dwLenBytes uint32) (random []byte, err error) {
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

//TODO: not implemented yet,there is not working stub
// GetDefaultProvider BOOL CryptGetDefaultProviderW(
//[in]      DWORD  dwProvType,
//[in]      DWORD  *pdwReserved,
//[in]      DWORD  dwFlags,
//[out]     LPWSTR pszProvName,
//[in, out] DWORD  *pcbProvName
//);
func (gost *GostCrypto) GetDefaultProvider() {
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
