package win32

import "unsafe"

type CryptoProvider struct {
	ProviderName string
	ProviderType uint32
}

type CryptoApiBlob struct {
	cbData uint32
	pbData *byte
}

// type LPWSTR unsafe.Pointer
type BYTE *byte

/*
	CryptSignMessagePara {
	  DWORD                       cbSize;
	  DWORD                       dwMsgEncodingType;
	  PCCERT_CONTEXT              pSigningCert;
	  CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;
	  void                        *pvHashAuxInfo;
	  DWORD                       cMsgCert;
	  PCCERT_CONTEXT              *rgpMsgCert;
	  DWORD                       cMsgCrl;
	  PCCRL_CONTEXT               *rgpMsgCrl;
	  DWORD                       cAuthAttr;
	  PCRYPT_ATTRIBUTE            rgAuthAttr;
	  DWORD                       cUnauthAttr;
	  PCRYPT_ATTRIBUTE            rgUnauthAttr;
	  DWORD                       dwFlags;
	  DWORD                       dwInnerContentType;
*/
type CryptSignMessagePara struct {
	cbSize             uint32
	dwMsgEncodingType  uint32
	pSigningCert       PCertContext
	HashAlgorithm      CryptAlgorithmIdentifier
	pvHashAuxInfo      unsafe.Pointer
	cMsgCert           uint32
	rgpMsgCert         PCertContext
	cMsgCrl            uint32
	rgpMsgCrl          *PCRLContext
	cAuthAttr          uint32
	rgAuthAttr         PCryptAttribute
	cUnauthAttr        uint32
	rgUnauthAttr       PCryptAttribute
	dwFlags            uint32
	dwInnerContentType uint32
}

type PCryptSignMessagePara CryptSignMessagePara

type (
	CertNameBlob      CryptoApiBlob
	CryptIntegerBlob  CryptoApiBlob
	IntegerBlob       CryptoApiBlob
	PcryptIntegerBlob *IntegerBlob
	CryptUintBlob     CryptoApiBlob
	PcryptUintBlob    *CryptUintBlob
	CryptObjidBlob    CryptoApiBlob
	PcryptObjidBlob   *CryptObjidBlob
	PcertNameBlob     *CertNameBlob
	CertRdnValueBlob  CryptoApiBlob
	PcertRdnValueBlob *CryptoApiBlob
	CertBlob          CryptoApiBlob
	PcertBlob         *CertBlob
	CrlBlob           CryptoApiBlob
	PcrlBlob          *CrlBlob
	DataBlob          CryptoApiBlob
	PdataBlob         *DataBlob
	CryptDataBlob     CryptoApiBlob
	PcryptDataBlob    *CryptDataBlob
	CryptHashBlob     CryptoApiBlob
	PcryptHashBlob    *CryptHashBlob
	CryptDigestBlob   CryptoApiBlob
	PcryptDigestBlob  *CryptDigestBlob
	CryptDerBlob      CryptoApiBlob
	PcryptDerBlob     *CryptDerBlob
	CryptAttrBlob     CryptoApiBlob
	PcryptAttrBlob    *CryptAttrBlob
)

type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type CryptBitBlob struct {
	Size       uint32
	Data       *byte
	UnusedBits uint32
}

type CryptAlgorithmIdentifier struct {
	ObjId      *byte
	Parameters CryptObjidBlob
}

type PublicKeyInfo struct {
	Algorithm CryptAlgorithmIdentifier
	PublicKey CryptBitBlob
}

type (
	CertPublicKeyInfo  PublicKeyInfo
	PcertPublicKeyInfo *PublicKeyInfo
)

type CertExtension struct {
	pszObjId  *uint16
	fCritical int32
	Value     CryptObjidBlob
}

type (
	PCertExtension *CertExtension
)

type CertInfo struct {
	dwVersion            uint32
	SerialNumber         CryptIntegerBlob
	SignatureAlgorithm   CryptAlgorithmIdentifier
	Issuer               CertNameBlob
	NotBefore            Filetime
	NotAfter             Filetime
	Subject              CertNameBlob
	SubjectPublicKeyInfo PublicKeyInfo
	IssuerUniqueId       CryptBitBlob
	SubjectUniqueId      CryptBitBlob
	cExtension           uint32
	rgExtension          PCertExtension
}

type PCertInfo *CertInfo

type CertContext struct {
	DwCertEncodingType uint32
	PbCertEncoded      *byte
	CbCertEncoded      uint32
	PCertInfo          PCertInfo
	HCERTSTORE         Handle
}

type PCertContext *CertContext

// PCRLContext TODO: that
type PCRLContext struct {
}

// PCryptAttribute TODO: and that
type PCryptAttribute struct {
}

type CryptSignMessageParaCmsField struct {
	CryptSignMessagePara
	pvHashEncryptionAuxInfo uintptr
	CryptAlgorithmIdentifier
}

type CryptEncryptMessagePara struct {
	HCryptProv                 *Handle
	ContentEncryptionAlgorithm CryptAlgorithmIdentifier
	CbSize                     uint32
	DwMsgEncodingType          uint32
	PvEncryptionAuxInfo        unsafe.Pointer //*void
	DwFlags                    uint32
	DwInnerContentType         uint32
}

type PCryptEncryptMessagePara *CryptEncryptMessagePara

type CryptKeyProvParam struct {
	dwParam uint32
	pbData  *byte
	cbData  uint32
	dwFlags uint32
}
type PCryptKeyProvParam *CryptKeyProvParam

type CryptKeyProvInfo struct {
	PwszContainerName *uint16
	PwszProvName      *uint16
	DwProvType        uint32
	DwFlags           uint32
	CProvParam        uint32
	RgProvParam       PCryptKeyProvParam
	DwKeySpec         uint32
}
type PCryptKeyProvInfo *CryptKeyProvInfo
