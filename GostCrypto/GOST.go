package GostCrypto

import (
	"fmt"
	win32 "github.com/SacredStar/Encryption.go/GostCrypto/Win32GoFunctions"
	"golang.org/x/sys/windows"
)

// Package provides d high level function. High-Level
// must be used ,except scenario that they don't provide expected behavior. Low Level presented and win32GoFunctions

type GostCrypto struct {
	hProvider win32.Handle
	hHash     win32.Handle
}

func (gost *GostCrypto) GetPtrToProviderHandle() *win32.Handle {
	return &gost.hProvider
}

func (gost *GostCrypto) GetPtrToHashHandle() *win32.Handle {
	return &gost.hHash
}

//
// Init and provider parameters function
//

//NewGostCrypto Initialisation function, get crypto provider context
func NewGostCrypto(container *uint16, provider *uint16, providerType win32.ProvType, flags win32.CryptAcquireContextDWFlagsParams) (*GostCrypto, error) {
	var hProvider win32.Handle
	if err := win32.CryptAcquireContext(&hProvider, container, provider, providerType, flags); err != nil {
		fmt.Println(err.Error())
		return &GostCrypto{}, err
	}
	return &GostCrypto{hProvider: hProvider}, nil
}

//
// Hash Functions
//

//CreateHashFromData creating hash for DataToHash with Hash-Alg algID
func (gost *GostCrypto) CreateHashFromData(algID win32.AlgoID, DataToHash []byte) (hVal []byte, err error) {
	lenData := len(DataToHash)
	if err := win32.CryptCreateHash(gost.hProvider, algID, 0, gost.GetPtrToHashHandle()); err != nil {
		return nil, err
	}
	if err := win32.CryptHashData(gost.hHash, &DataToHash[0], uint32(lenData), 0); err != nil {
		return nil, err
	}
	if hVal, err := gost.cryptGetHashParamFull(win32.HP_HASHVAL, 0, algID); err != nil {
		return nil, err
	} else {
		return hVal, nil
	}
	//TODO: defer CryptReleaseHash?
}

func (gost *GostCrypto) cryptGetHashParamFull(dwParam win32.DwParam, dwFlags uint32, algID win32.AlgoID) (HashedData []byte, err error) {
	var size int
	if algID == win32.CALG_GR3411 || algID == win32.CALG_GR3411_2012_256 || algID == win32.CALG_GR3411_2012_256_HMAC {
		size = 32
	}
	if algID == win32.CALG_GR3411_2012_512 || algID == win32.CALG_GR3411_2012_512_HMAC {
		size = 64
	}
	var pbData = make([]byte, size)
	pdwDataLen := uint32(size)
	if err := win32.CryptGetHashParam(
		win32.Handle(gost.hHash),
		dwParam,
		&pbData[0],
		&pdwDataLen,
		dwFlags); err != nil {
		return nil, err
	}
	return pbData, nil
}

// GetProviderName return name of the current crypto provider ctx
func (gost *GostCrypto) GetProviderName() (param []byte, err error) {
	var pdwDataLen uint32
	//Получаем размер буфера для pbData
	if err := win32.CryptGetProvParam(
		gost.hProvider,
		win32.PP_NAME,
		nil,
		&pdwDataLen,
		0); err != nil {
		return nil, err
	}
	//Создаем переменную для записи
	pbData := make([]byte, pdwDataLen)

	if err := win32.CryptGetProvParam(
		gost.hProvider,
		win32.PP_NAME,
		&pbData[0],
		&pdwDataLen,
		0); err != nil {
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
func (gost *GostCrypto) EnumProviders() (providers []*win32.CryptoProvider, err error) {
	var dwIndex, pdwProvType, pcbProvName uint32

	dwIndex = 0
	for {
		if err := win32.CryptEnumProviders(dwIndex, nil, 0, &pdwProvType, nil, &pcbProvName); err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				return providers, nil
			} else {
				return nil, err
			}
		}
		szProvName := make([]byte, pcbProvName)

		if err := win32.CryptEnumProviders(dwIndex, nil, 0, &pdwProvType, &szProvName[0], &pcbProvName); err != nil {
			return nil, err
		}
		providers = append(providers, &win32.CryptoProvider{
			ProviderName: string(szProvName),
			ProviderType: pdwProvType,
		})
		dwIndex++
	}
}
