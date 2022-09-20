package win32

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

type GetSetProviderParams int

//goland:noinspection GoSnakeCaseUsage
const (
	PP_CLIENT_HWND                     GetSetProviderParams = 1
	PP_CONTEXT_INFO                    GetSetProviderParams = 11
	PP_KEYEXCHANGE_KEYSIZE             GetSetProviderParams = 12
	PP_SIGNATURE_KEYSIZE               GetSetProviderParams = 13
	PP_KEYEXCHANGE_ALG                 GetSetProviderParams = 14
	PP_SIGNATURE_ALG                   GetSetProviderParams = 15
	PP_DELETEKEY                       GetSetProviderParams = 24
	PP_PIN_PROMPT_STRING               GetSetProviderParams = 44
	PP_SECURE_KEYEXCHANGE_PIN          GetSetProviderParams = 47
	PP_SECURE_SIGNATURE_PIN            GetSetProviderParams = 48
	PP_ADMIN_PIN                       GetSetProviderParams = 0x1F
	PP_NAME                            GetSetProviderParams = 0x4
	PP_APPLI_CERT                      GetSetProviderParams = 0x12
	PP_CHANGE_PASSWORD                 GetSetProviderParams = 0x7
	PP_CONTAINER                       GetSetProviderParams = 0x6
	PP_CRYPT_COUNT_KEY_USE             GetSetProviderParams = 0x29
	PP_ENUMALGS                        GetSetProviderParams = 0x1
	PP_ENUMALGS_EX                     GetSetProviderParams = 0x16
	PP_ENUMCONTAINERS                  GetSetProviderParams = 0x2
	PP_ENUMELECTROOTS                  GetSetProviderParams = 0x1A
	PP_ENUMEX_SIGNING_PROT             GetSetProviderParams = 0x28
	PP_ENUMMANDROOTS                   GetSetProviderParams = 0x19
	PP_IMPTYPE                         GetSetProviderParams = 0x3
	PP_KEY_TYPE_SUBTYPE                GetSetProviderParams = 0xA
	PP_KEYEXCHANGE_PIN                 GetSetProviderParams = 0x20
	PP_KEYSET_SEC_DESCR                GetSetProviderParams = 0x8
	PP_KEYSET_TYPE                     GetSetProviderParams = 0x1B
	PP_KEYSPEC                         GetSetProviderParams = 0x27
	PP_KEYSTORAGE                      GetSetProviderParams = 0x11
	PP_KEYX_KEYSIZE_INC                GetSetProviderParams = 0x23
	PP_PROVTYPE                        GetSetProviderParams = 0x10
	PP_ROOT_CERTSTORE                  GetSetProviderParams = 0x2E
	PP_SESSION_KEYSIZE                 GetSetProviderParams = 0x14
	PP_SGC_INFO                        GetSetProviderParams = 0x25
	PP_SIG_KEYSIZE_INC                 GetSetProviderParams = 0x22
	PP_SIGNATURE_PIN                   GetSetProviderParams = 0x21
	PP_SMARTCARD_GUID                  GetSetProviderParams = 0x2D
	PP_SMARTCARD_READER                GetSetProviderParams = 0x2B
	PP_SYM_KEYSIZE                     GetSetProviderParams = 0x13
	PP_UI_PROMPT                       GetSetProviderParams = 0x15
	PP_UNIQUE_CONTAINER                GetSetProviderParams = 0x24
	PP_USE_HARDWARE_RNG                GetSetProviderParams = 0x26
	PP_USER_CERTSTORE                  GetSetProviderParams = 0x2A
	PP_VERSION                         GetSetProviderParams = 0x5
	PP_ENUMALGSGetProvParam            GetSetProviderParams = 1
	PP_ENUMCONTAINERSGetProvParam      GetSetProviderParams = 2
	PP_IMPTYPEGetProvParam             GetSetProviderParams = 3
	PP_NAMEGetProvParam                GetSetProviderParams = 4
	PP_VERSIONGetProvParam             GetSetProviderParams = 5
	PP_CERTCHAIN                       GetSetProviderParams = 9 // for retrieving certificates from tokens
	PP_KEY_TYPE_SUBTYPEGetProvParam    GetSetProviderParams = 10
	PP_USE_HARDWARE_RNGGetProvParam    GetSetProviderParams = 38
	PP_ENUMEX_SIGNING_PROTGetProvParam GetSetProviderParams = 40
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
	//AT_SYMMETRIC ??
)

type DwParam uint32

//goland:noinspection GoSnakeCaseUsage
const (
	KP_IV               DwParam = 1  // Initialization vector
	KP_SALT             DwParam = 2  // Salt value
	KP_PADDING          DwParam = 3  // Padding values
	KP_MODE             DwParam = 4  // Mode of the cipher
	KP_MODE_BITS        DwParam = 5  // Number of bits to feedback
	KP_PERMISSIONS      DwParam = 6  // Key permissions DWORD
	KP_ALGID            DwParam = 7  // Key algorithm
	KP_BLOCKLEN         DwParam = 8  // Block size of the cipher
	KP_KEYLEN           DwParam = 9  // Length of key in bits
	KP_SALT_EX          DwParam = 10 // Length of salt in bytes
	KP_P                DwParam = 11 // DSS/Diffie-Hellman P value
	KP_G                DwParam = 12 // DSS/Diffie-Hellman G value
	KP_Q                DwParam = 13 // DSS Q value
	KP_X                DwParam = 14 // Diffie-Hellman X value
	KP_Y                DwParam = 15 // Y value
	KP_RA               DwParam = 16 // Fortezza RA value
	KP_RB               DwParam = 17 // Fortezza RB value
	KP_INFO             DwParam = 18 // for putting information into an RSA envelope
	KP_EFFECTIVE_KEYLEN DwParam = 19 // setting and getting RC2 effective key length
	KP_SCHANNEL_ALG     DwParam = 20 // for setting the Secure Channel algorithms
	KP_CLIENT_RANDOM    DwParam = 21 // for setting the Secure Channel client random data
	KP_SERVER_RANDOM    DwParam = 22 // for setting the Secure Channel server random data
	KP_RP               DwParam = 23
	KP_PRECOMP_MD5      DwParam = 24
	KP_PRECOMP_SHA      DwParam = 25
	KP_CERTIFICATE      DwParam = 26 // for setting Secure Channel certificate data (PCT1)
	KP_CLEAR_KEY        DwParam = 27 // for setting Secure Channel clear key data (PCT1)
	KP_PUB_EX_LEN       DwParam = 28
	KP_PUB_EX_VAL       DwParam = 29
	KP_KEYVAL           DwParam = 30
	KP_ADMIN_PIN        DwParam = 31
	KP_KEYEXCHANGE_PIN  DwParam = 32
	KP_SIGNATURE_PIN    DwParam = 33
	KP_PREHASH          DwParam = 34
	KP_ROUNDS           DwParam = 35
	KP_OAEP_PARAMS      DwParam = 36 // for setting OAEP params on RSA keys
	KP_CMS_KEY_INFO     DwParam = 37
	KP_CMS_DH_KEY_INFO  DwParam = 38
	KP_PUB_PARAMS       DwParam = 39 // for setting public parameters
	KP_VERIFY_PARAMS    DwParam = 40 // for verifying DSA and DH parameters
	KP_HIGHEST_VERSION  DwParam = 41 // for TLS protocol version setting
	KP_GET_USE_COUNT    DwParam = 42 // for use with PP_CRYPT_COUNT_KEY_USE contexts
	KP_PIN_ID           DwParam = 43
	KP_PIN_INFO         DwParam = 44

	////KP_PADDING

	PKCS5_PADDING  DwParam = 1 // PKCS 5 (sec 6.2) padding method
	RANDOM_PADDING DwParam = 2
	ZERO_PADDING   DwParam = 3

	////KP_MODE

	CRYPT_MODE_CBC DwParam = 1 // Cipher block chaining
	CRYPT_MODE_ECB DwParam = 2 // Electronic code book
	CRYPT_MODE_OFB DwParam = 3 // Output feedback mode
	CRYPT_MODE_CFB DwParam = 4 // Cipher feedback mode
	CRYPT_MODE_CTS DwParam = 5 // Ciphertext stealing mode

	//// KP_PERMISSIONS

	CRYPT_ENCRYPT    DwParam = 0x0001 // Allow encryption
	CRYPT_DECRYPT    DwParam = 0x0002 // Allow decryption
	CRYPT_EXPORT     DwParam = 0x0004 // Allow key to be exported
	CRYPT_READ       DwParam = 0x0008 // Allow parameters to be read
	CRYPT_WRITE      DwParam = 0x0010 // Allow parameters to be set
	CRYPT_MAC        DwParam = 0x0020 // Allow MACs to be used with key
	CRYPT_EXPORT_KEY DwParam = 0x0040 // Allow key to be used for exporting keys
	CRYPT_IMPORT_KEY DwParam = 0x0080 // Allow key to be used for importing keys

	HP_ALGID         DwParam = 0x0001 // Hash algorithm
	HP_HASHSTARTVECT DwParam = 0x0008
	HP_HASHCOPYVAL   DwParam = 0x0009
	HP_OID           DwParam = 0x000a
	HP_OPEN          DwParam = 0x000B
	HP_OPAQUEBLOB    DwParam = 0x000C
	HP_HASHVAL       DwParam = 0x0002 // Hash value
	HP_HASHSIZE      DwParam = 0x0004 // Hash value size
	HP_HMAC_INFO     DwParam = 0x0005 // information for creating an HMAC
	HP_TLS1PRF_LABEL DwParam = 0x0006 // label for TLS1 PRF
	HP_TLS1PRF_SEED  DwParam = 0x0007 // seed for TLS1 PRF

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

type NTEErrors uint32

const (
	NTE_BAD_UID                   NTEErrors = 0x80090001
	NTE_BAD_HASH                  NTEErrors = 0x80090002
	NTE_BAD_KEY                   NTEErrors = 0x80090003
	NTE_BAD_LEN                   NTEErrors = 0x80090004
	NTE_BAD_DATA                  NTEErrors = 0x80090005
	NTE_BAD_SIGNATURE             NTEErrors = 0x80090006
	NTE_BAD_VER                   NTEErrors = 0x80090007
	NTE_BAD_ALGID                 NTEErrors = 0x80090008
	NTE_BAD_FLAGS                 NTEErrors = 0x80090009
	NTE_BAD_TYPE                  NTEErrors = 0x8009000A
	NTE_BAD_KEY_STATE             NTEErrors = 0x8009000B
	NTE_BAD_HASH_STATE            NTEErrors = 0x8009000C
	NTE_NO_KEY                    NTEErrors = 0x8009000D
	NTE_NO_MEMORY                 NTEErrors = 0x8009000E
	NTE_EXISTS                    NTEErrors = 0x8009000F
	NTE_PERM                      NTEErrors = 0x80090010
	NTE_NOT_FOUND                 NTEErrors = 0x80090011
	NTE_DOUBLE_ENCRYPT            NTEErrors = 0x80090012
	NTE_BAD_PROVIDER              NTEErrors = 0x80090013
	NTE_BAD_PROV_TYPE             NTEErrors = 0x80090014
	NTE_BAD_PUBLIC_KEY            NTEErrors = 0x80090015
	NTE_BAD_KEYSET                NTEErrors = 0x80090016
	NTE_PROV_TYPE_NOT_DEF         NTEErrors = 0x80090017
	NTE_PROV_TYPE_ENTRY_BAD       NTEErrors = 0x80090018
	NTE_KEYSET_NOT_DEF            NTEErrors = 0x80090019
	NTE_KEYSET_ENTRY_BAD          NTEErrors = 0x8009001A
	NTE_PROV_TYPE_NO_MATCH        NTEErrors = 0x8009001B
	NTE_SIGNATURE_FILE_BAD        NTEErrors = 0x8009001C
	NTE_PROVIDER_DLL_FAIL         NTEErrors = 0x8009001D
	NTE_PROV_DLL_NOT_FOUND        NTEErrors = 0x8009001E
	NTE_BAD_KEYSET_PARAM          NTEErrors = 0x8009001F
	NTE_FAIL                      NTEErrors = 0x80090020
	NTE_SYS_ERR                   NTEErrors = 0x80090021
	NTE_SILENT_CONTEXT            NTEErrors = 0x80090022
	NTE_TOKEN_KEYSET_STORAGE_FULL NTEErrors = 0x80090023
	NTE_TEMPORARY_PROFILE         NTEErrors = 0x80090024
	NTE_FIXEDPARAMETER            NTEErrors = 0x80090025
	NTE_INVALID_HANDLE            NTEErrors = 0x80090026
	NTE_INVALID_PARAMETER         NTEErrors = 0x80090027
	NTE_BUFFER_TOO_SMALL          NTEErrors = 0x80090028
	NTE_NOT_SUPPORTED             NTEErrors = 0x80090029
	NTE_NO_MORE_ITEMS             NTEErrors = 0x8009002A
	NTE_BUFFERS_OVERLAP           NTEErrors = 0x8009002B
	NTE_DECRYPTION_FAILURE        NTEErrors = 0x8009002C
	NTE_INTERNAL_ERROR            NTEErrors = 0x8009002D
	NTE_UI_REQUIRED               NTEErrors = 0x8009002E
	NTE_HMAC_NOT_SUPPORTED        NTEErrors = 0x8009002F
	NTE_DEVICE_NOT_READY          NTEErrors = 0x80090030
	NTE_AUTHENTICATION_IGNORED    NTEErrors = 0x80090031
	NTE_VALIDATION_FAILED         NTEErrors = 0x80090032
	NTE_INCORRECT_PASSWORD        NTEErrors = 0x80090033
	NTE_ENCRYPTION_FAILURE        NTEErrors = 0x80090034
	NTE_DEVICE_NOT_FOUND          NTEErrors = 0x80090035
	NTE_USER_CANCELLED            NTEErrors = 0x80090036
	NTE_PASSWORD_CHANGE_REQUIRED  NTEErrors = 0x80090037
	NTE_NOT_ACTIVE_CONSOLE        NTEErrors = 0x80090038
)
