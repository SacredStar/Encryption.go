package GostCrypto

import "syscall"

type Handle uintptr

//Initializing libs for future usage, must use Lazy dll to prevent leaking
var (
	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procCryptAcquireContext     = advapi32.NewProc("CryptAcquireContextW")
	procCryptEnumProviders      = advapi32.NewProc("CryptEnumProvidersW")
	procCryptGetDefaultProvider = advapi32.NewProc("CryptGetDefaultProviderW")
	procCryptGetProviderParam   = advapi32.NewProc("CryptGetProvParam")
	procCryptCreateHash         = advapi32.NewProc("CryptCreateHash")
	procCryptHashData           = advapi32.NewProc("CryptHashData")
	procGetHashParam            = advapi32.NewProc("CryptGetHashParam")
	procCryptGenRandom          = advapi32.NewProc("CryptGenRandom")
)

type CryptoProvider struct {
	ProviderName string
	ProviderType uint32
}

type AlgoID uint32

//Идентификаторы алгоритмов
//goland:noinspection GoSnakeCaseUsage
const (
	// CALG_GR3410EL Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2001.
	CALG_GR3410EL AlgoID = 0x2e23

	// CALG_GR3410_2012_256 Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (256 бит).
	CALG_GR3410_2012_256 AlgoID = 0x2e49

	// CALG_GR3410_2012_512 Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (512 бит).
	CALG_GR3410_2012_512 AlgoID = 0x2e3d

	// CALG_GR3411 Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
	CALG_GR3411 AlgoID = 0x801e

	// CALG_GR3411_2012_256 Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
	CALG_GR3411_2012_256 AlgoID = 0x8021

	// CALG_GR3411_2012_512 Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
	CALG_GR3411_2012_512 AlgoID = 0x8022

	// CALG_GR3411_HMAC Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа.
	CALG_GR3411_HMAC AlgoID = 0x8027

	// CALG_GR3411_2012_256_HMAC Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа  длина выхода 256 бит.
	CALG_GR3411_2012_256_HMAC AlgoID = 0x8034

	// CALG_GR3411_2012_512_HMAC Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа  длина выхода 512 бит.
	CALG_GR3411_2012_512_HMAC AlgoID = 0x8035

	// CALG_GR3411_HMAC34 Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма хэширования по ГОСТ Р 34.11.
	CALG_GR3411_HMAC34 AlgoID = 0x8028
)

//goland:noinspection ALL
const (
	InvalidAlgSpecified = "Invalid algorithm specified."
	InvalidParameter    = "The parameter is incorrect."
)
