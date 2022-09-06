package GostCrypto

/* File provides wincrypt.h redefinitions for golang native usage */

// Base CryptoPro Provider Type params

type ProvType uint32

// Provider types

//goland:noinspection GoSnakeCaseUsage
const (
	ProvGost94       ProvType = 71
	ProvGost2001     ProvType = 75
	ProvGost2012     ProvType = 80
	ProvGost2012_512 ProvType = 81
)

//CryptAcquireContext Params

type CryptAcquireContextDWFlagsParams uint32

//goland:noinspection GoSnakeCaseUsage
const (
	CRYPT_VERIFYCONTEXT  CryptAcquireContextDWFlagsParams = 0xF0000000
	CRYPT_NEWKEYSET      CryptAcquireContextDWFlagsParams = 0x00000008
	CRYPT_DELETEKEYSET   CryptAcquireContextDWFlagsParams = 0x00000010
	CRYPT_MACHINE_KEYSET CryptAcquireContextDWFlagsParams = 0x00000020
	CRYPT_SILENT         CryptAcquireContextDWFlagsParams = 0x00000040
)

// Export Key Params

type ExportKeyParams uint32

//goland:noinspection GoSnakeCaseUsage
const (
	CRYPT_Y_ONLY        ExportKeyParams = 0x00000001
	CRYPT_SSL2_FALLBACK ExportKeyParams = 0x00000002
	CRYPT_DESTROYKEY    ExportKeyParams = 0x00000004
	CRYPT_OAEP          ExportKeyParams = 0x00000040
)

//Gen Keys Params

type GenKeyParams uint32 //TODO: check parameter type

//goland:noinspection GoSnakeCaseUsage
const (
	CRYPT_EXPORTABLE     GenKeyParams = 0x00000001
	CRYPT_USER_PROTECTED GenKeyParams = 0x00000002
	CRYPT_CREATE_SALT    GenKeyParams = 0x00000004
	CRYPT_UPDATE_KEY     GenKeyParams = 0x00000008
	CRYPT_NO_SALT        GenKeyParams = 0x00000010
	CRYPT_PREGEN         GenKeyParams = 0x00000040
	CRYPT_RECIPIENT      GenKeyParams = 0x00000010
	CRYPT_INITIATOR      GenKeyParams = 0x00000040
	CRYPT_ONLINE         GenKeyParams = 0x00000080
	CRYPT_SF             GenKeyParams = 0x00000100
	CRYPT_CREATE_IV      GenKeyParams = 0x00000200
	CRYPT_KEK            GenKeyParams = 0x00000400
	CRYPT_DATA_KEY       GenKeyParams = 0x00000800
	CRYPT_VOLATILE       GenKeyParams = 0x00001000
	CRYPT_SGCKEY         GenKeyParams = 0x00002000
)

//Get Provider Params

type GetProviderParams int

//goland:noinspection GoSnakeCaseUsage
const (
	PP_ADMIN_PIN                       GetProviderParams = 0x1F
	PP_NAME                            GetProviderParams = 0x4
	PP_APPLI_CERT                      GetProviderParams = 0x12
	PP_CHANGE_PASSWORD                 GetProviderParams = 0x7
	PP_CONTAINER                       GetProviderParams = 0x6
	PP_CRYPT_COUNT_KEY_USE             GetProviderParams = 0x29
	PP_ENUMALGS                        GetProviderParams = 0x1
	PP_ENUMALGS_EX                     GetProviderParams = 0x16
	PP_ENUMCONTAINERS                  GetProviderParams = 0x2
	PP_ENUMELECTROOTS                  GetProviderParams = 0x1A
	PP_ENUMEX_SIGNING_PROT             GetProviderParams = 0x28
	PP_ENUMMANDROOTS                   GetProviderParams = 0x19
	PP_IMPTYPE                         GetProviderParams = 0x3
	PP_KEY_TYPE_SUBTYPE                GetProviderParams = 0xA
	PP_KEYEXCHANGE_PIN                 GetProviderParams = 0x20
	PP_KEYSET_SEC_DESCR                GetProviderParams = 0x8
	PP_KEYSET_TYPE                     GetProviderParams = 0x1B
	PP_KEYSPEC                         GetProviderParams = 0x27
	PP_KEYSTORAGE                      GetProviderParams = 0x11
	PP_KEYX_KEYSIZE_INC                GetProviderParams = 0x23
	PP_PROVTYPE                        GetProviderParams = 0x10
	PP_ROOT_CERTSTORE                  GetProviderParams = 0x2E
	PP_SESSION_KEYSIZE                 GetProviderParams = 0x14
	PP_SGC_INFO                        GetProviderParams = 0x25
	PP_SIG_KEYSIZE_INC                 GetProviderParams = 0x22
	PP_SIGNATURE_PIN                   GetProviderParams = 0x21
	PP_SMARTCARD_GUID                  GetProviderParams = 0x2D
	PP_SMARTCARD_READER                GetProviderParams = 0x2B
	PP_SYM_KEYSIZE                     GetProviderParams = 0x13
	PP_UI_PROMPT                       GetProviderParams = 0x15
	PP_UNIQUE_CONTAINER                GetProviderParams = 0x24
	PP_USE_HARDWARE_RNG                GetProviderParams = 0x26
	PP_USER_CERTSTORE                  GetProviderParams = 0x2A
	PP_VERSION                         GetProviderParams = 0x5
	PP_ENUMALGSGetProvParam            GetProviderParams = 1
	PP_ENUMCONTAINERSGetProvParam      GetProviderParams = 2
	PP_IMPTYPEGetProvParam             GetProviderParams = 3
	PP_NAMEGetProvParam                GetProviderParams = 4
	PP_VERSIONGetProvParam             GetProviderParams = 5
	PP_CERTCHAIN                       GetProviderParams = 9 // for retrieving certificates from tokens
	PP_KEY_TYPE_SUBTYPEGetProvParam    GetProviderParams = 10
	PP_USE_HARDWARE_RNGGetProvParam    GetProviderParams = 38
	PP_ENUMEX_SIGNING_PROTGetProvParam GetProviderParams = 40
)

// Create hash Params

type CryptCreateHashParams uint32

//goland:noinspection GoSnakeCaseUsage
const (
	CRYPT_SECRETDIGEST CryptCreateHashParams = 0x00000001
)

// CryptHashSessionKey Params(dwParams)

type CryptHashSessionKeydwParams uint32

//goland:noinspection GoSnakeCaseUsage
const CRYPT_LITTLE_ENDIAN CryptHashSessionKeydwParams = 0x00000001

// dwFlags definitions for CryptSignHash and CryptVerifySignature

type SignHashVerifySigndwFlags uint32

//goland:noinspection GoSnakeCaseUsage
const (
	CRYPT_NOHASHOID    SignHashVerifySigndwFlags = 0x00000001
	CRYPT_TYPE2_FORMAT SignHashVerifySigndwFlags = 0x00000002 // Not supported
	CRYPT_X931_FORMAT  SignHashVerifySigndwFlags = 0x00000004 // Not supported
)

// dwFlag definitions for CryptSetProviderEx and CryptGetDefaultProvider

type CryptSetProviderGetDefaultProvDWFlag uint32

//goland:noinspection GoSnakeCaseUsage
const (
	CRYPT_MACHINE_DEFAULT CryptSetProviderGetDefaultProvDWFlag = 0x00000001
	CRYPT_USER_DEFAULT    CryptSetProviderGetDefaultProvDWFlag = 0x00000002
	CRYPT_DELETE_DEFAULT  CryptSetProviderGetDefaultProvDWFlag = 0x00000004
)

// exported key blob definitions

type KeyBlobParams uint32

const (
	SIMPLEBLOB           KeyBlobParams = 0x1
	PUBLICKEYBLOB        KeyBlobParams = 0x6
	PRIVATEKEYBLOB       KeyBlobParams = 0x7
	PLAINTEXTKEYBLOB     KeyBlobParams = 0x8
	OPAQUEKEYBLOB        KeyBlobParams = 0x9
	PUBLICKEYBLOBEX      KeyBlobParams = 0xA
	SYMMETRICWRAPKEYBLOB KeyBlobParams = 0xB
)

// certenrolld

type certEnrollParams uint32

//goland:noinspection GoSnakeCaseUsage
const (
	AT_KEYEXCHANGE certEnrollParams = 1
	AT_SIGNATURE   certEnrollParams = 2
)

type dwParam uint32

//goland:noinspection GoSnakeCaseUsage
const (
	KP_IV               dwParam = 1  // Initialization vector
	KP_SALT             dwParam = 2  // Salt value
	KP_PADDING          dwParam = 3  // Padding values
	KP_MODE             dwParam = 4  // Mode of the cipher
	KP_MODE_BITS        dwParam = 5  // Number of bits to feedback
	KP_PERMISSIONS      dwParam = 6  // Key permissions DWORD
	KP_ALGID            dwParam = 7  // Key algorithm
	KP_BLOCKLEN         dwParam = 8  // Block size of the cipher
	KP_KEYLEN           dwParam = 9  // Length of key in bits
	KP_SALT_EX          dwParam = 10 // Length of salt in bytes
	KP_P                dwParam = 11 // DSS/Diffie-Hellman P value
	KP_G                dwParam = 12 // DSS/Diffie-Hellman G value
	KP_Q                dwParam = 13 // DSS Q value
	KP_X                dwParam = 14 // Diffie-Hellman X value
	KP_Y                dwParam = 15 // Y value
	KP_RA               dwParam = 16 // Fortezza RA value
	KP_RB               dwParam = 17 // Fortezza RB value
	KP_INFO             dwParam = 18 // for putting information into an RSA envelope
	KP_EFFECTIVE_KEYLEN dwParam = 19 // setting and getting RC2 effective key length
	KP_SCHANNEL_ALG     dwParam = 20 // for setting the Secure Channel algorithms
	KP_CLIENT_RANDOM    dwParam = 21 // for setting the Secure Channel client random data
	KP_SERVER_RANDOM    dwParam = 22 // for setting the Secure Channel server random data
	KP_RP               dwParam = 23
	KP_PRECOMP_MD5      dwParam = 24
	KP_PRECOMP_SHA      dwParam = 25
	KP_CERTIFICATE      dwParam = 26 // for setting Secure Channel certificate data (PCT1)
	KP_CLEAR_KEY        dwParam = 27 // for setting Secure Channel clear key data (PCT1)
	KP_PUB_EX_LEN       dwParam = 28
	KP_PUB_EX_VAL       dwParam = 29
	KP_KEYVAL           dwParam = 30
	KP_ADMIN_PIN        dwParam = 31
	KP_KEYEXCHANGE_PIN  dwParam = 32
	KP_SIGNATURE_PIN    dwParam = 33
	KP_PREHASH          dwParam = 34
	KP_ROUNDS           dwParam = 35
	KP_OAEP_PARAMS      dwParam = 36 // for setting OAEP params on RSA keys
	KP_CMS_KEY_INFO     dwParam = 37
	KP_CMS_DH_KEY_INFO  dwParam = 38
	KP_PUB_PARAMS       dwParam = 39 // for setting public parameters
	KP_VERIFY_PARAMS    dwParam = 40 // for verifying DSA and DH parameters
	KP_HIGHEST_VERSION  dwParam = 41 // for TLS protocol version setting
	KP_GET_USE_COUNT    dwParam = 42 // for use with PP_CRYPT_COUNT_KEY_USE contexts
	KP_PIN_ID           dwParam = 43
	KP_PIN_INFO         dwParam = 44

	////KP_PADDING

	PKCS5_PADDING  dwParam = 1 // PKCS 5 (sec 6.2) padding method
	RANDOM_PADDING dwParam = 2
	ZERO_PADDING   dwParam = 3

	////KP_MODE

	CRYPT_MODE_CBC dwParam = 1 // Cipher block chaining
	CRYPT_MODE_ECB dwParam = 2 // Electronic code book
	CRYPT_MODE_OFB dwParam = 3 // Output feedback mode
	CRYPT_MODE_CFB dwParam = 4 // Cipher feedback mode
	CRYPT_MODE_CTS dwParam = 5 // Ciphertext stealing mode

	//// KP_PERMISSIONS

	CRYPT_ENCRYPT    dwParam = 0x0001 // Allow encryption
	CRYPT_DECRYPT    dwParam = 0x0002 // Allow decryption
	CRYPT_EXPORT     dwParam = 0x0004 // Allow key to be exported
	CRYPT_READ       dwParam = 0x0008 // Allow parameters to be read
	CRYPT_WRITE      dwParam = 0x0010 // Allow parameters to be set
	CRYPT_MAC        dwParam = 0x0020 // Allow MACs to be used with key
	CRYPT_EXPORT_KEY dwParam = 0x0040 // Allow key to be used for exporting keys
	CRYPT_IMPORT_KEY dwParam = 0x0080 // Allow key to be used for importing keys

	HP_ALGID         dwParam = 0x0001 // Hash algorithm
	HP_HASHVAL       dwParam = 0x0002 // Hash value
	HP_HASHSIZE      dwParam = 0x0004 // Hash value size
	HP_HMAC_INFO     dwParam = 0x0005 // information for creating an HMAC
	HP_TLS1PRF_LABEL dwParam = 0x0006 // label for TLS1 PRF
	HP_TLS1PRF_SEED  dwParam = 0x0007 // seed for TLS1 PRF

)

// key storage flags

type KeyStorageFlags uint32

//goland:noinspection GoSnakeCaseUsage
const (
	CRYPT_SEC_DESCR KeyStorageFlags = 0x00000001
	CRYPT_PSTORE    KeyStorageFlags = 0x00000002
	CRYPT_UI_PROMPT KeyStorageFlags = 0x00000004
)

// protocol flags

type ProtoFlags uint32

//goland:noinspection GoSnakeCaseUsage
const (
	CRYPT_FLAG_PCT1    ProtoFlags = 0x0001
	CRYPT_FLAG_SSL2    ProtoFlags = 0x0002
	CRYPT_FLAG_SSL3    ProtoFlags = 0x0004
	CRYPT_FLAG_TLS1    ProtoFlags = 0x0008
	CRYPT_FLAG_IPSEC   ProtoFlags = 0x0010
	CRYPT_FLAG_SIGNING ProtoFlags = 0x0020
)

//
// CryptSetProvParam

type SetProvParams uint32

//goland:noinspection GoSnakeCaseUsage
const (
	PP_CLIENT_HWND            SetProvParams = 1
	PP_CONTEXT_INFO           SetProvParams = 11
	PP_KEYEXCHANGE_KEYSIZE    SetProvParams = 12
	PP_SIGNATURE_KEYSIZE      SetProvParams = 13
	PP_KEYEXCHANGE_ALG        SetProvParams = 14
	PP_SIGNATURE_ALG          SetProvParams = 15
	PP_DELETEKEY              SetProvParams = 24
	PP_PIN_PROMPT_STRING      SetProvParams = 44
	PP_SECURE_KEYEXCHANGE_PIN SetProvParams = 47
	PP_SECURE_SIGNATURE_PIN   SetProvParams = 48
)
