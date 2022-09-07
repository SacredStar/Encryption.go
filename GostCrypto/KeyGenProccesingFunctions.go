package GostCrypto

import "unsafe"

//
// Key generation and processing function
//

//CryptGenKey
//[in]  HCRYPTPROV hProv,
//[in]  ALG_ID     Algid, //TODO: need to add algs to constans.go and change algID type
//[in]  DWORD      dwFlags,
//[out] HCRYPTKEY  *phKey(handle)
func CryptGenKey(provHandle, algID uint32, dwFlags GenKeyParams, keyHandle *Handle) (err error) {
	if r1, _, err := procCryptGenKey.Call(
		uintptr(provHandle),
		uintptr(algID),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(keyHandle))); r1 == 0 {
		return err
	}
	return nil
}

// CryptDestroyKey
//[in] HCRYPTKEY hKey
func CryptDestroyKey(keyHandle Handle) (err error) {
	if r1, _, err := procCryptDestroyKey.Call(
		uintptr(keyHandle)); r1 == 0 {
		return err
	}
	return nil

}

// CryptDeriveKey
//  [in]      HCRYPTPROV hProv,
//  [in]      ALG_ID     Algid (symmetric encryption): CALG_G28147,CALG_TLS1_ENC_KEY,CALG_TLS1_MAC_KEY,CALG_UECSYMMETRIC CALG_UECSYMMETRIC_EPHEM CALG_G28147 TODO: need to add algs to constans.go and change algID type
//  [in]      HCRYPTHASH hBaseData : descriptor of hasher
//  [in]      DWORD      dwFlags GenKeyParams:CRYPT_EXPORTABLE,CRYPT_SERVER,CP_CRYPT_GETUPPERKEY
//  [in, out] HCRYPTKEY  *phKey
func CryptDeriveKey(handleProvider Handle, algID uint32, handleHash Handle, params GenKeyParams, keyHandle Handle) (err error) {
	if r1, _, err := procCryptDeriveKey.Call(
		uintptr(handleProvider),
		uintptr(algID),
		uintptr(handleHash),
		uintptr(params),
		uintptr(keyHandle)); r1 == 0 {
		return err
	}
	return nil
}

// CryptDuplicateKey
//  [in]  HCRYPTKEY hKey: src
//  [in]  DWORD     *pdwReserved = 0: reserved for future
//  [in]  DWORD     dwFlags = 0 : reserved for future
//  [out] HCRYPTKEY *phKey : copy
func CryptDuplicateKey(handleKey Handle, pdwReserved uintptr, dwFlags uint32, handleKeyCopy *Handle) (err error) {
	if r1, _, err := procCryptDuplicateKey.Call(
		uintptr(handleKey),
		uintptr(pdwReserved),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(handleKeyCopy))); r1 == 0 {
		return err
	}
	return nil
}

// CryptExportKey
//[in]      HCRYPTKEY hKey,
//[in]      HCRYPTKEY hExpKey,
//[in]      DWORD     dwBlobType: for WL must use only PUBLICKEYBLOB param
//[in]      DWORD     dwFlags, for WL: or CRYPT_PUBLICCOMPRESS
//[out]     BYTE      *pbData,
//[in, out] DWORD     *pdwDataLen
func CryptExportKey(handleKey Handle, hExportKey Handle, dwBlobType KeyBlobParams, dwFlags uint32, pbData *byte, pdwDataLen *uint32) (err error) {
	if r1, _, err := procCryptExportKey.Call(
		uintptr(handleKey),
		uintptr(hExportKey),
		uintptr(dwBlobType),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(pbData)),
		uintptr(unsafe.Pointer(pdwDataLen))); r1 == 0 {
		return err
	}
	return nil
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

// CryptGetKeyParam
//  [in]      HCRYPTKEY hKey,
//  [in]      DWORD     dwParam,
//  [out]     BYTE      *pbData,
//  [in, out] DWORD     *pdwDataLen,
//  [in]      DWORD     dwFlags =0 : reserved for future
func CryptGetKeyParam(hKey Handle, dwParams dwParam, pdData *byte, pdwDataLen *uint32, dwFlags uint32) (err error) {
	if r1, _, err := procCryptGetKeyParam.Call(
		uintptr(hKey),
		uintptr(dwParams),
		uintptr(unsafe.Pointer(pdData)),
		uintptr(unsafe.Pointer(pdwDataLen)),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}

// CryptGetUserKey
//  [in]  HCRYPTPROV hProv,
//  [in]  DWORD      dwKeySpec,
//  [out] HCRYPTKEY  *phUserKey
func CryptGetUserKey(hProv Handle, dwKeySpecs certEnrollParams, phUserKey *Handle) (err error) {
	if r1, _, err := procCryptGetUserKey.Call(
		uintptr(hProv),
		uintptr(dwKeySpecs),
		uintptr(unsafe.Pointer(phUserKey))); r1 == 0 {
		return err
	}
	return nil

}

// CryptImportKey
//  [in]  HCRYPTPROV hProv
//  [in]  const BYTE *pbData Указатель на буфер, содержащий ключевой блоб, произведенный с иcпользованием функции CPExportKey()
//  [in]  DWORD      dwDataLen
//  [in]  HCRYPTKEY  hPubKey A handle to the cryptographic key that decrypts the key stored in pbData
//  [in]  DWORD      dwFlags Значение флага. Этот параметр в настоящее время используется только, когда ключевая пара импортируется в криптопровайдер (в форме PRIVATEKEYBLOB).
//                            Если импортируемый ключ будет заново экспортироваться, в этот параметр помещается флаг CRYPT_EXPORTABLE.
//                            Если этот флаг не используется, вызовы функции CryptExportKey в MS CryptoAPI 2.0  с дескриптором ключа будут терпеть неудачу.
//  [out] HCRYPTKEY  *phKey  Адрес, по которому функция копирует дескриптор импортированного либо диверсифицированного ключа.
func CryptImportKey(hProv Handle, pbData *byte, dwDataLen uint32, hPubKey Handle, dwFlags GenKeyParams, phKey *Handle) (err error) {
	if r1, _, err := procCryptImportKey.Call(
		uintptr(hProv),
		uintptr(unsafe.Pointer(pbData)),
		uintptr(dwDataLen),
		uintptr(hPubKey),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(phKey))); r1 == 0 {
		return err
	}
	return nil
}

// CryptSetKeyParam //TODO: check is needed  [in]  HCRYPTPROV hProv?
//  [in] HCRYPTKEY  hKey,
//  [in] DWORD      dwParam, WL: KP_CERTIFICATE, KP_CIPHEROID, KP_DHOID,KP_HASHOID
//  [in] const BYTE *pbData,
//  [in] DWORD      dwFlags = 0 reserved for future
func CryptSetKeyParam(hKey Handle, param dwParam, pbData *byte, flag CryptSetProviderGetDefaultProvDWFlag) (err error) {
	if r1, _, err := procCryptImportKey.Call(
		//uintptr(hProv),
		uintptr(unsafe.Pointer(hKey)),
		uintptr(param),
		uintptr(unsafe.Pointer(pbData)),
		uintptr(flag)); r1 == 0 {
		return err
	}
	return nil
}
