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
	procCryptSetKeyParam  = advapi32.NewProc("CryptImportKey")

	procCryptEnumProviders      = advapi32.NewProc("CryptEnumProvidersW")
	procCryptGetDefaultProvider = advapi32.NewProc("CryptGetDefaultProviderW")

	procCryptCreateHash = advapi32.NewProc("CryptCreateHash")
	procCryptHashData   = advapi32.NewProc("CryptHashData")
	procGetHashParam    = advapi32.NewProc("CryptGetHashParam")
)

type CryptoProvider struct {
	ProviderName string
	ProviderType uint32
}
