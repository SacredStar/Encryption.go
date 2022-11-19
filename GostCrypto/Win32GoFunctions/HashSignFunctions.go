package win32

import (
	"unsafe"
)

// CryptCreateHash
//  [in]  HCRYPTPROV hProv, Дескриптор криптопровайдера
//  [in]  ALG_ID     Algid Идентификатор используемого алгоритма хэширования
//  [in]  HCRYPTKEY  hKey =0 Если используется алгоритм имитозащиты по ГОСТ 28147-89 (CALG_G28147_IMIT), в этом параметре передаётся ключ сессии для объекта функции хэширования
//  [in]  DWORD      DwFlags, Значения флагов. При создании объекта HMAC возможно указать флаг CP_REUSABLE_HMAC для повышения эффективности повторного использования
//  [out] HCRYPTHASH *phHash Адрес по которому функция копирует дескриптор нового объекта функции хэширования
func CryptCreateHash(hProvider Handle, algID AlgoID, hKey Handle, hashHandle *Handle) error {
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

// CryptDestroyHash
//  [in] HCRYPTHASH hHash
func CryptDestroyHash(handleHash Handle) (err error) {
	if r1, _, err := procCryptDestroyHash.Call(
		uintptr(unsafe.Pointer(handleHash))); r1 == 0 {
		return err
	}
	return nil
}

// CryptDuplicateHash
//  [in]  HCRYPTHASH hHash,
//  [in]  DWORD      *pdwReserved = 0 Reserved for future
//  [in]  DWORD      DwFlags =0 , Reserved for future
//  [out] HCRYPTHASH *phHash , дескриптор нового объекта функции хэширования.
func CryptDuplicateHash(handleHash Handle, pdwReserved *uint32, dwFlags uint32, phHash *Handle) (err error) {
	if r1, _, err := procCryptDuplicateHash.Call(
		uintptr(handleHash),
		uintptr(unsafe.Pointer(pdwReserved)),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(phHash))); r1 == 0 {
		return err
	}
	return nil
}

// CryptGetHashParam
//  [in]      HCRYPTHASH hHash,
//  [in]      DWORD      dwParam, HP_ALGID,HP_HASHSIZE,HP_HASHVAL,HP_R2_SIGN,HP_R_SIGN,HP_SHAREDMODE,HP_IKE_SPI_COOKIE
//  [out]     BYTE       *pbData, Указатель на буфер данных параметра
//  [in, out] DWORD      *pdwDataLen Указатель на буфер, содержащий длину данных параметра.
//  [in]      DWORD      DwFlags = 0 reserved
func CryptGetHashParam(hHash Handle, dwParam DwParam, pbData *byte, pdwDataLen *uint32, dwFlags uint32) (err error) {

	if r1, _, err := procGetHashParam.Call(
		uintptr(hHash),
		uintptr(dwParam),
		uintptr(unsafe.Pointer(pbData)),
		uintptr(unsafe.Pointer(pdwDataLen)),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}

//CryptHashData
// [in] HCRYPTHASH hHash,
// [in] BYTE *pbData, Если значение DwFlags нулевое, указатель на буфер, содержащий данные для хэширования
// [in] DWORD      dwDataLen, Если значение DwFlags нулевое, число байтов хэшируемых данных
// [in] DWORD      DwFlags  Значения флагов CPIOVec or 0
func CryptHashData(hHash Handle, pbData *byte, dwDataLen uint32, dwFlags uint32) error {
	if r1, _, err := procCryptHashData.Call(
		uintptr(hHash),
		uintptr(unsafe.Pointer(pbData)),
		uintptr(dwDataLen),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}

// CryptHashSessionKey
//  [in] HCRYPTHASH hHash,
//  [in] HCRYPTKEY  hKey,
//  [in] DWORD      DwFlags CRYPT_LITTLE_ENDIAN or 0 //TODO: странная приписка Использование функции с DwFlags равным 0 не рекомендуется - поведение не определено.
func CryptHashSessionKey(handleHash Handle, handleKey Handle, dwFlags CryptHashSessionKeydwParams) (err error) {
	if r1, _, err := procCryptHashSessionKey.Call(
		uintptr(handleHash),
		uintptr(handleKey),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}

//CryptSetHashParam
//  [in] HCRYPTHASH hHash,
//  [in] DWORD      dwParam, HP_HASHVAL,HP_HASHSIZE....
//  [in] const BYTE *pbData, Указатель на буфер данных параметра
//  [in] DWORD      DwFlags =0 Reserved
func CryptSetHashParam(handleHash Handle, param DwParam, pdData *byte, dwFlags DwParam) (err error) {
	if r1, _, err := procCryptSetHashParam.Call(
		uintptr(handleHash),
		uintptr(param),
		uintptr(unsafe.Pointer(pdData)),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}

// CryptSignHash
//  [in]      HCRYPTHASH hHash,
//  [in]      DWORD      dwKeySpec: AT_KEYEXCHANGE or AT_SIGNATURE
//  [in]      LPCWSTR    szDescription, /TODO: check type
//  [in]      DWORD      DwFlags =0 ,reserved for future
//  [out]     BYTE       *pbSignature Указатель на буфер, через который возвращается значение подписи. Если через этот параметр передаётся NULL, то подпись не вычисляется. В этом случае требуемый размер буфера (в байтах) возвращается через параметр pdwSigLen.
//  [in, out] DWORD      *pdwSigLen Указатель на буфер, содержащий длину данных подписи
func CryptSignHash(hHash Handle, dwKeySpecs CertEnrollParams, szDescription *byte, dwFlags uint32, pbSignature *byte, pdwSigLen *uint32) (err error) {
	if r1, _, err := procCryptSignHash.Call(
		uintptr(hHash),
		uintptr(dwKeySpecs),
		uintptr(unsafe.Pointer(szDescription)),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(pbSignature)),
		uintptr(unsafe.Pointer(pdwSigLen))); r1 == 0 {
		return err
	}
	return nil
}

// CryptVerifySignature
//  [in] HCRYPTHASH hHash,
//  [in] const BYTE *pbSignature, Указатель на буфер, содержащий значение проверяемой подписи.
//  [in] DWORD      dwSigLen, Длина (в байтах) значения подписи.
//  [in] HCRYPTKEY  hPubKey, Дескриптор открытого ключа проверяемой подписи.
//  [in] LPCWSTR    szDescription, Описание подписанных данных идентичное описанию, использованному при создании подписи.
//  [in] DWORD      DwFlags =0, reserved for future use
func CryptVerifySignature(hHash Handle, pbSignature *byte, dwSiglen uint32, hPubKey Handle, szDescription *byte, dwFlags int) (err error) {
	if r1, _, err := procCryptVerifySignature.Call(
		uintptr(hHash),
		uintptr(unsafe.Pointer(pbSignature)),
		uintptr(dwSiglen),
		uintptr(hPubKey),
		uintptr(unsafe.Pointer(szDescription)),
		uintptr(dwFlags)); r1 == 0 {
		return err
	}
	return nil
}
