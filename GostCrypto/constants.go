package GostCrypto

import "syscall"

type ProvType uint32

// Provider types
const (
	ProvGost94       ProvType = 71
	ProvGost2001     ProvType = 75
	ProvGost2012     ProvType = 80
	ProvGost2012_512 ProvType = 81
)

//Initializing libs for future usage, must use Laze dll to prevent leaking
var (
	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procCryptEnumProviders      = advapi32.NewProc("CryptEnumProvidersW")
	procCryptGetDefaultProvider = advapi32.NewProc("CryptGetDefaultProviderW")
	procCryptGetProviderParam   = advapi32.NewProc("CryptGetProvParam")
	procCryptCreateHash         = advapi32.NewProc("CryptCreateHash")
	procCryptHashData           = advapi32.NewProc("CryptHashData")
	procGetHashParam            = advapi32.NewProc("CryptGetHashParam")
	procCryptGenRandom          = advapi32.NewProc("CryptGenRandom")
)

type GetProviderParams int

//ProviderParams
const (
	PP_ADMIN_PIN           GetProviderParams = 0x1F
	PP_NAME                GetProviderParams = 0x4
	PP_APPLI_CERT          GetProviderParams = 0x12
	PP_CHANGE_PASSWORD     GetProviderParams = 0x7
	PP_CONTAINER           GetProviderParams = 0x6
	PP_CRYPT_COUNT_KEY_USE GetProviderParams = 0x29
	PP_ENUMALGS            GetProviderParams = 0x1
	PP_ENUMALGS_EX         GetProviderParams = 0x16
	PP_ENUMCONTAINERS      GetProviderParams = 0x2
	PP_ENUMELECTROOTS      GetProviderParams = 0x1A
	PP_ENUMEX_SIGNING_PROT GetProviderParams = 0x28
	PP_ENUMMANDROOTS       GetProviderParams = 0x19
	PP_IMPTYPE             GetProviderParams = 0x3
	PP_KEY_TYPE_SUBTYPE    GetProviderParams = 0xA
	PP_KEYEXCHANGE_PIN     GetProviderParams = 0x20
	PP_KEYSET_SEC_DESCR    GetProviderParams = 0x8
	PP_KEYSET_TYPE         GetProviderParams = 0x1B
	PP_KEYSPEC             GetProviderParams = 0x27
	PP_KEYSTORAGE          GetProviderParams = 0x11
	PP_KEYX_KEYSIZE_INC    GetProviderParams = 0x23
	PP_PROVTYPE            GetProviderParams = 0x10
	PP_ROOT_CERTSTORE      GetProviderParams = 0x2E
	PP_SESSION_KEYSIZE     GetProviderParams = 0x14
	PP_SGC_INFO            GetProviderParams = 0x25
	PP_SIG_KEYSIZE_INC     GetProviderParams = 0x22
	PP_SIGNATURE_PIN       GetProviderParams = 0x21
	PP_SMARTCARD_GUID      GetProviderParams = 0x2D
	PP_SMARTCARD_READER    GetProviderParams = 0x2B
	PP_SYM_KEYSIZE         GetProviderParams = 0x13
	PP_UI_PROMPT           GetProviderParams = 0x15
	PP_UNIQUE_CONTAINER    GetProviderParams = 0x24
	PP_USE_HARDWARE_RNG    GetProviderParams = 0x26
	PP_USER_CERTSTORE      GetProviderParams = 0x2A
	PP_VERSION             GetProviderParams = 0x5
)

type CryptoProvider struct {
	ProviderName string
	ProviderType uint32
}

type AlgorythmID uint32

//Идентификаторы алгоритмов
const (
	// CALG_GR3410EL Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2001.
	CALG_GR3410EL AlgorythmID = 0x2e23

	// CALG_GR3410_2012_256 Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (256 бит).
	CALG_GR3410_2012_256 AlgorythmID = 0x2e49

	// CALG_GR3410_2012_512 Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (512 бит).
	CALG_GR3410_2012_512 AlgorythmID = 0x2e3d

	// CALG_GR3411 Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
	CALG_GR3411 AlgorythmID = 0x801e

	// CALG_GR3411_2012_256 Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
	CALG_GR3411_2012_256 AlgorythmID = 0x8021

	// CALG_GR3411_2012_512 Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
	CALG_GR3411_2012_512 AlgorythmID = 0x8022

	// CALG_GR3411_HMAC Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа <see cref="CALG_G28147"/>.
	CALG_GR3411_HMAC AlgorythmID = 0x8027

	// CALG_GR3411_2012_256_HMAC Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа <see cref="CALG_G28147"/>, длина выхода 256 бит.
	CALG_GR3411_2012_256_HMAC AlgorythmID = 0x8034

	// CALG_GR3411_2012_512_HMAC Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа <see cref="CALG_G28147"/>, длина выхода 512 бит.
	CALG_GR3411_2012_512_HMAC AlgorythmID = 0x8035

	// CALG_GR3411_HMAC34 Идентификатор алгоритма ключевого хэширования (HMAC, Hash-based Message Authentication Code) на базе алгоритма хэширования по ГОСТ Р 34.11.
	CALG_GR3411_HMAC34 AlgorythmID = 0x8028
)

const (
	HP_HASHVAL uint32 = 0x0002
)

const (
	InvalidAlgSpecified = "Invalid algorithm specified."
	InvalidParameter    = "The parameter is incorrect."
)
