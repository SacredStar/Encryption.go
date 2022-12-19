package win32

import (
	"syscall"
)

type Handle uintptr

//Initializing libs for future usage, must use Lazy dll to prevent leaking
var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	crypt32  = syscall.NewLazyDLL("Crypt32.dll")
	//kernel32 = syscall.NewLazyDLL("Kernel32.dll")

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
	procCryptEncryptMessage                 = crypt32.NewProc("CryptEncryptMessage")
	procCryptDecryptMessage                 = crypt32.NewProc("CryptDecryptMessage")

	//Other crypto process
	procCryptEnumProviders                = advapi32.NewProc("CryptEnumProvidersW")
	procCertOpenSystemStore               = crypt32.NewProc("CertOpenSystemStoreW")
	procCertFindCertificateInStore        = crypt32.NewProc("CertFindCertificateInStore")
	procCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")
	procCryptAcquireCertificatePrivateKey = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
	procCertNameToStr                     = crypt32.NewProc("CertNameToStrW")

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

	//Utility Function
	//procGetLastError = kernel32.NewProc("GetLastError")
)
