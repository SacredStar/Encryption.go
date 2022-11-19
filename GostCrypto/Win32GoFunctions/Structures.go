package win32

type CryptoProvider struct {
	ProviderName string
	ProviderType uint32
}

type CryptoapiBlob struct {
	cbData uint32
	pbData *byte
}

type CryptSignMessagePara struct {
	cbSize             uint32
	dwMsgEncodingType  uint32
	pSigningCert       PCertContext
	HashAlgorithm      CryptAlgorithmIdentifier
	pvHashAuxInfo      *uintptr
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

type cryptoapiBlob struct {
	cbData uint32
	pbData *byte
}

type (
	CertNameBlob      cryptoapiBlob
	CryptIntegerBlob  cryptoapiBlob
	IntegerBlob       cryptoapiBlob
	PcryptIntegerBlob *IntegerBlob
	CryptUintBlob     cryptoapiBlob
	PcryptUintBlob    *CryptUintBlob
	CryptObjidBlob    cryptoapiBlob
	PcryptObjidBlob   *CryptObjidBlob
	PcertNameBlob     *CertNameBlob
	CertRdnValueBlob  cryptoapiBlob
	PcertRdnValueBlob *cryptoapiBlob
	CertBlob          cryptoapiBlob
	PcertBlob         *CertBlob
	CrlBlob           cryptoapiBlob
	PcrlBlob          *CrlBlob
	DataBlob          cryptoapiBlob
	PdataBlob         *DataBlob
	CryptDataBlob     cryptoapiBlob
	PcryptDataBlob    *CryptDataBlob
	CryptHashBlob     cryptoapiBlob
	PcryptHashBlob    *CryptHashBlob
	CryptDigestBlob   cryptoapiBlob
	PcryptDigestBlob  *CryptDigestBlob
	CryptDerBlob      cryptoapiBlob
	PcryptDerBlob     *CryptDerBlob
	CryptAttrBlob     cryptoapiBlob
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
	pszObjId  uintptr
	fCritical bool
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

type HCertStore Handle

type CertContext struct {
	DwCertEncodingType uint32
	PbCertEncoded      *byte
	CbCertEncoded      uint32
	PCertInfo          PCertInfo
	HCERTSTORE         HCertStore
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
	HCryptProv                 Handle
	ContentEncryptionAlgorithm CryptAlgorithmIdentifier
	CbSize                     uint32
	DwMsgEncodingType          uint32
	PvEncryptionAuxInfo        *uint32
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
	PwszContainerName uintptr
	PwszProvName      uintptr
	DwProvType        uint32
	DwFlags           uint32
	CProvParam        uint32
	RgProvParam       CryptKeyProvParam
	DwKeySpec         uint32
}
type PCryptKeyProvInfo *CryptKeyProvInfo
