package win32

import (
	"fmt"
	"unsafe"
)

//CryptEnumProviders
//  [in]      DWORD  dwIndex, Index of the next provider to be enumerated.
//  [in]      DWORD  *pdwReserved =0,
//  [in]      DWORD  DwFlags =0,
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

// CertOpenSystemStore
//  [in] HCRYPTPROV_LEGACY hProv ,
//  [in] LPCWSTR           szSubsystemProtocol Строка, именующая системное хранилище
func CertOpenSystemStore(hProv Handle, szSubsystemProtocol *uint16) (HSystemStore Handle, err error) {
	r1, _, err := procCertOpenSystemStore.Call(
		uintptr(hProv),
		uintptr(unsafe.Pointer(szSubsystemProtocol)))
	if r1 == 0 {
		return Handle(0), err
	} else {
		HSystemStore = Handle(r1)
	}

	return HSystemStore, nil
}

// CertFindCertificateInStore
//  [in] HCERTSTORE     hCertStore, A handle of the certificate store to be searched.
//  [in] DWORD          dwCertEncodingType, X509_ASN_ENCODING PKCS_7_ASN_ENCODING
//  [in] DWORD          dwFindFlags, Used with some dwFindType values to modify the search criteria. For most dwFindType values, dwFindFlags is not used and should be set to zero.
//  [in] DWORD          dwFindType, Specifies the type of search being made
//  [in] const void     *pvFindPara,
//  [in] PCCERT_CONTEXT pPrevCertContext
func CertFindCertificateInStore(store Handle, dwCertEncodingType uint32, dwFindFlags uint32, dwFindType uint32, pvFindPara Handle, pPrevCertContext PCertContext) (CertCtx *CertContext, err error) {
	r1, _, err := procCertFindCertificateInStore.Call(
		uintptr(store),
		uintptr(dwCertEncodingType),
		uintptr(dwFindFlags),
		uintptr(dwFindType),
		uintptr(pvFindPara),
		uintptr(unsafe.Pointer(pPrevCertContext)))
	//TODO: check this
	if r1 == 0 {
		fmt.Println(err.Error())
		return nil, err
	}
	cert := (*CertContext)(unsafe.Pointer(r1))
	return cert, nil
}

// CertGetCertificateContextProperty BOOL
//  [in]      PCCERT_CONTEXT pCertContext,
//  [in]      DWORD          dwPropId,
//  [out]     void           *pvData,
//  [in, out] DWORD          *pcbData
func CertGetCertificateContextProperty(Certctx PCertContext, dwPropId uint32, pvData *Handle, pcbData *uint32) (err error) {
	r1, _, err := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(Certctx)),
		uintptr(dwPropId),
		uintptr(unsafe.Pointer(pvData)),
		uintptr(unsafe.Pointer(pcbData)),
	)
	if r1 == 0 {
		return err
	}
	return nil

}

//CryptAcquireCertificatePrivateKey BOOL
//  [in]           PCCERT_CONTEXT                  pCert,
//  [in]           DWORD                           dwFlags,
//  [in, optional] void                            *pvParameters,
//  [out]          HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey, Currently work only with HCryptProv
//  [out]          DWORD                           *pdwKeySpec,
//  [out]          BOOL                            *pfCallerFreeProvOrNCryptKey Currently work only with freeprov
func CryptAcquireCertificatePrivateKey(pCert PCertContext, dwFlags uint32, pvParameters Handle, phCryptProvOrNCryptKey Handle, pdwKeySpec *uint32, pfCallerFreeProvOrNCryptKey *bool) (err error) {
	r1, _, err := procCryptAcquireCertificatePrivateKey.Call(
		uintptr(unsafe.Pointer(pCert)),
		uintptr(dwFlags),
		uintptr(pvParameters),
		uintptr(phCryptProvOrNCryptKey),
		uintptr(unsafe.Pointer(pdwKeySpec)),
		uintptr(unsafe.Pointer(pfCallerFreeProvOrNCryptKey)),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

// CertNameToStr uint32
//  Returns the number of characters converted, including the terminating null character.
//  [in]  DWORD           dwCertEncodingType, The certificate encoding type that was used to encode the name.
//  [in]  PCERT_NAME_BLOB pName, A pointer to the CERT_NAME_BLOB structure to be converted.
//  [in]  DWORD           dwStrType, This parameter specifies the format of the output string
//  [out] LPWSTR          psz, A pointer to a character buffer that receives the returned string
//  [in]  DWORD           csz The size, in characters, of the psz buffer. The size must include the terminating null character.
func CertNameToStr(dwCertEncodingType uint32, pName PcertNameBlob, dwStrType uint32, psz *uint16, csz uint32) (NumOfChars uintptr, err error) {
	r1, _, err := procCertNameToStr.Call(
		uintptr(dwCertEncodingType),
		uintptr(unsafe.Pointer(pName)),
		uintptr(dwStrType),
		uintptr(unsafe.Pointer(psz)),
		uintptr(csz))
	if r1 == 0 {
		return 0, err
	}
	return r1, nil
}
