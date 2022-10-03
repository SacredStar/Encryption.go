package win32

import "syscall"

type Handle uintptr

//Initializing libs for future usage, must use Lazy dll to prevent leaking
var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	// Init and provider parameters process
	procCryptAcquireContext   = advapi32.NewProc("CryptAcquireContextW")
	procCryptReleaseContext   = advapi32.NewProc("CryptReleaseContext")
	procCryptGetProviderParam = advapi32.NewProc("CryptGetProvParam")
	procCryptSetProviderParam = advapi32.NewProc("CryptSetProvParam")

	//Keys process
	procCryptGenKey       = advapi32.NewProc("CryptGenKey")
	procCryptDestroyKey   = advapi32.NewProc("CryptDestroyKey")
	procCryptDeriveKey    = advapi32.NewProc("CryptDeriveKey")
	procCryptDuplicateKey = advapi32.NewProc("CryptDuplicateKey")
	procCryptExportKey    = advapi32.NewProc("CryptExportKey")
	procCryptGenRandom    = advapi32.NewProc("CryptGenRandom")
	procCryptGetKeyParam  = advapi32.NewProc("CryptGetKeyParam")
	procCryptGetUserKey   = advapi32.NewProc("CryptGetUserKey")
	procCryptImportKey    = advapi32.NewProc("CryptImportKey")
	procCryptSetKeyParam  = advapi32.NewProc("CryptSetKeyParam")

	// CMS
	procCryptSignMessage                    = advapi32.NewProc("CryptSignMessage")
	procCryptVerifyMessageSignature         = advapi32.NewProc("CryptVerifyMessageSignature")
	procCryptVerifyDetachedMessageSignature = advapi32.NewProc("CryptVerifyDetachedMessageSignature")
	procCryptDecodeMessage                  = advapi32.NewProc("CryptDecodeMessage")
	procCryptEncryptMessage                 = advapi32.NewProc("CryptEncryptMessage")
	procCryptDecryptMessage                 = advapi32.NewProc("CryptDecryptMessage")
	procCryptGetMessageCertificates         = advapi32.NewProc("CryptGetMessageCertificates")
	procCryptGetMessageSignerCount          = advapi32.NewProc("CryptGetMessageSignerCount")
	procCryptHashMessage                    = advapi32.NewProc("CryptHashMessage")
	procCryptSignAndEncryptMessage          = advapi32.NewProc("CryptSignAndEncryptMessage")
	procCryptSignMessageWithKey             = advapi32.NewProc("CryptSignMessageWithKey")
	procCryptMsgCalculateEncodedLength      = advapi32.NewProc("CryptMsgCalculateEncodedLength")
	procCryptMsgOpenToEncode                = advapi32.NewProc("CryptMsgOpenToEncode")
	procCryptMsgOpenToDecode                = advapi32.NewProc("CryptMsgOpenToDecode")
	procCryptMsgUpdate                      = advapi32.NewProc("CryptMsgUpdate")
	procCryptMsgGetParam                    = advapi32.NewProc("CryptMsgGetParam")
	procCryptMsgControl                     = advapi32.NewProc("CryptMsgControl")
	procCryptMsgClose                       = advapi32.NewProc("CryptMsgClose")
	procCryptMsgDuplicate                   = advapi32.NewProc("CryptMsgDuplicate")

	//Other crypto process
	procCryptEnumProviders = advapi32.NewProc("CryptEnumProvidersW")
	//procCryptGetDefaultProvider = advapi32.NewProc("CryptGetDefaultProviderW")

	//Hash and Sign process
	procCryptCreateHash      = advapi32.NewProc("CryptCreateHash")
	procCryptDestroyHash     = advapi32.NewProc("CryptDestroyHash")
	procCryptDuplicateHash   = advapi32.NewProc("CryptDuplicateHash")
	procGetHashParam         = advapi32.NewProc("CryptGetHashParam")
	procCryptHashData        = advapi32.NewProc("CryptHashData")
	procCryptHashSessionKey  = advapi32.NewProc("CryptHashSessionKey")
	procCryptSetHashParam    = advapi32.NewProc("CryptSetHashParam")
	procCryptSignHash        = advapi32.NewProc("CryptSignHashW")
	procCryptVerifySignature = advapi32.NewProc("CryptVerifySignatureW")
)

type CryptoProvider struct {
	ProviderName string
	ProviderType uint32
}

type CryptoapiBlob struct {
	cbData uint32
	pbData *byte
}

type CryptAlgorithmIdentifier struct {
	pszObjId   string
	Parameters CryptoapiBlob
}

type CryptEncryptMessagePara struct {
	hCryptProv                 Handle
	ContentEncryptionAlgorithm CryptAlgorithmIdentifier
	cbSize                     uint32
	dwMsgEncodingType          uint32
	pvEncryptionAuxInfo        *uint32
	dwFlags                    uint32
	dwInnerContentType         uint32
}
