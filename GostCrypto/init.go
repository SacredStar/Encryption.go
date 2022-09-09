package GostCrypto

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

	//Other crypto process
	procCryptEnumProviders      = advapi32.NewProc("CryptEnumProvidersW")
	procCryptGetDefaultProvider = advapi32.NewProc("CryptGetDefaultProviderW")

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
