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

//TODO: from that position
// CryptExportKey
//[in]      HCRYPTKEY hKey,
//[in]      HCRYPTKEY hExpKey,
//[in]      DWORD     dwBlobType,
//[in]      DWORD     dwFlags,
//[out]     BYTE      *pbData,
//[in, out] DWORD     *pdwDataLen
func CryptExportKey() {

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
//  [in]      DWORD     dwFlags
func CryptGetKeyParam() {

}

// CryptGetUserKey
//  [in]  HCRYPTPROV hProv,
//  [in]  DWORD      dwKeySpec,
//  [out] HCRYPTKEY  *phUserKey
func CryptGetUserKey() {

}

// CryptImportKey [in]  HCRYPTPROV hProv,
//  [in]  const BYTE *pbData,
//  [in]  DWORD      dwDataLen,
//  [in]  HCRYPTKEY  hPubKey,
//  [in]  DWORD      dwFlags,
//  [out] HCRYPTKEY  *phKey
func CryptImportKey() {

}

// CryptSetKeyParam
//  [in] HCRYPTKEY  hKey,
//  [in] DWORD      dwParam,
//  [in] const BYTE *pbData,
//  [in] DWORD      dwFlags
func CryptSetKeyParam() {

}
