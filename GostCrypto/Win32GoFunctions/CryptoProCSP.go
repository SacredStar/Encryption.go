package win32

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

	/*
		CALG_GR3411 Идентификатор алгоритма хэширования по ГОСТ Р 34.11-94.
		CALG_GR3411_2012_256 Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
		CALG_GR3411_2012_512 Идентификатор алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
		CALG_G28147_MAC Идентификатор алгоритма имитозащиты по ГОСТ 28147-89.
		CALG_G28147_IMIT  То же самое, что и CALG_G28147_MAC (устаревшая версия).
		CALG_GR3410  Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-94.
		CALG_GR3410EL  Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2001.
		CALG_GR3410_12_256  Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (256 бит).
		CALG_GR3410_12_512  Идентификатор алгоритма ЭЦП по ГОСТ Р 34.10-2012 (512 бит).
		CALG_GR3411_HMAC  Идентификатор алгоритма ключевого хэширования на базе алгоритма ГОСТ Р 34.11-94 и сессионного ключа CALG_G28147.
		CALG_GR3411_2012_256_HMAC  Идентификатор алгоритма ключевого хэширования на базе алгоритма ГОСТ Р 34.11-2012 и сессионного ключа CALG_G28147, длина выхода 256 бит.
		CALG_GR3411_2012_512_HMAC  Идентификатор алгоритма ключевого хэширования на базе алгоритма ГОСТ Р 34.11-2012 и сессионного ключа CALG_G28147, длина выхода 512 бит.
		CALG_G28147 Идентификатор алгоритма шифрования по ГОСТ 28147-89.
		CALG_SYMMETRIC_512 Идентификатор алгоритма выработки ключа парной связи по Диффи-Хеллману с длиной выхода 512 бит.
		CALG_DH_EX_SF  Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя.
		CALG_DH_EX_EPHEM  Идентификатор CALG_DH_EX алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 94.
		CALG_DH_EX  Идентификатор CALG_DH_EX алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 94.
		CALG_DH_EL_SF  Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2001.
		CALG_DH_EL_EPHEM Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2001.
		CALG_DH_GR3410_12_256_SF Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2012 (256 бит).
		CALG_DH_GR3410_12_256_EPHEM Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2012 (256 бит).
		CALG_DH_GR3410_12_512_SF Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа пользователя. Открытый ключ получается по ГОСТ Р 34.10 2012 (512 бит).
		CALG_DH_GR3410_12_512_EPHEM Идентификатор алгоритма обмена ключей по Диффи-Хеллману на базе закрытого ключа эфемерной пары. Открытый ключ получается по ГОСТ Р 34.10 2012 (512 бит).
		CALG_PRO_AGREEDKEY_DH Идентификатор алгоритма выработки ключа парной связи по Диффи-Хеллману.
		CALG_PRO_EXPORT  Идентификатор алгоритма защищённого экспорта ключа.
		CALG_PRO12_EXPORT  Идентификатор алгоритма защищённого экспорта ключа по рекомендациям ТК26 (обязателен для использования с ключами ГОСТ Р 34.10-2012).
		CALG_SIMPLE_EXPORT  Идентификатор алгоритма простого экспорта ключа.
		CALG_TLS1PRF Идентификатор алгоритма "производящей функции" (PRF) протокола TLS 1.0 на основе алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
		СALG_TLS1PRF_2012_256 Идентификатор алгоритма "производящей функции" (PRF) протокола TLS 1.0 на основе алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012.
		CALG_TLS1_MASTER_HASH Идентификатор алгоритма выработки объекта MASTER_HASH протокола TLS 1.0 на основе алгоритма хэширования в соответствии с ГОСТ Р 34.11-94.
		CALG_TLS1_MASTER_HASH_2012_256 Идентификатор алгоритма выработки объекта MASTER_HASH протокола TLS 1.0 на основе алгоритма хэширования в соответствии с ГОСТ Р 34.11-2012.
		CALG_TLS1_MAC_KEY Идентификатор алгоритма выработки ключа имитозащиты протокола TLS 1.0.
		CALG_TLS1_ENC_KEY  Идентификатор алгоритма выработки ключа шифрования протокола TLS 1.0.
		CALG_PBKDF2_94_256 Идентификатор алгоритма выработки ключа из пароля на основе алгоритма хэширования в соответвии с ГОСТ Р 34.11-94, длина выхода 256 бит.
		CALG_PBKDF2_2012_256 Идентификатор алгоритма выработки ключа из пароля на основе алгоритма хэширования в соответвии с ГОСТ Р 34.11-2012, длина выхода 256 бит.
		CALG_PBKDF2_2012_512 Идентификатор алгоритма выработки ключа из пароля на основе алгоритма хэширования в соответвии с ГОСТ Р 34.11-2012, длина выхода 512 бит.
		CALG_PRO_DIVERS Идентификатор алгоритма КриптоПро диверсификации ключа по RFC 4357.
		CALG_PRO12_DIVERS Идентификатор алгоритма КриптоПро диверсификации ключа по рекомендациям ТК26.
		CALG_RIC_DIVERS Идентификатор алгоритма РИК диверсификации ключа.
	*/
)

//goland:noinspection ALL
const (
	InvalidAlgSpecified = "Invalid algorithm specified."
	InvalidParameter    = "The parameter is incorrect."
)

const (
	//CRYPT_PRIVATE_KEYS_ALG_OID_GROUP_ID
	SzOID_CP_GOST_PRIVATE_KEYS_V1        = "1.2.643.2.2.37.1"
	SzOID_CP_GOST_PRIVATE_KEYS_V2        = "1.2.643.2.2.37.2"
	SzOID_CP_GOST_PRIVATE_KEYS_V2_FULL   = "1.2.643.2.2.37.2.1"
	SzOID_CP_GOST_PRIVATE_KEYS_V2_PARTOF = "1.2.643.2.2.37.2.2"

	//CRYPT_HASH_ALG_OID_GROUP_ID
	SzOID_CP_GOST_R3411        = "1.2.643.2.2.9"
	SzOID_CP_GOST_R3411_12_256 = "1.2.643.7.1.1.2.2"
	SzOID_CP_GOST_R3411_12_512 = "1.2.643.7.1.1.2.3"

	//CRYPT_ENCRYPT_ALG_OID_GROUP_ID
	SzOID_CP_GOST_28147                       = "1.2.643.2.2.21"
	SzOID_CP_GOST_R3412_2015_M                = "1.2.643.7.1.1.5.1"
	SzOID_CP_GOST_R3412_2015_K                = "1.2.643.7.1.1.5.2"
	SzOID_CP_GOST_R3412_2015_M_CTR_ACPKM      = "1.2.643.7.1.1.5.1.1"
	SzOID_CP_GOST_R3412_2015_M_CTR_ACPKM_OMAC = "1.2.643.7.1.1.5.1.2"
	SzOID_CP_GOST_R3412_2015_K_CTR_ACPKM      = "1.2.643.7.1.1.5.2.1"
	SzOID_CP_GOST_R3412_2015_K_CTR_ACPKM_OMAC = "1.2.643.7.1.1.5.2.2"

	SzOID_CP_GOST_R3412_2015_M_KEXP15 = "1.2.643.7.1.1.7.1.1"
	SzOID_CP_GOST_R3412_2015_K_KEXP15 = "1.2.643.7.1.1.7.2.1"

	//CRYPT_PUBKEY_ALG_OID_GROUP_ID
	SzOID_CP_GOST_R3410         = "1.2.643.2.2.20"
	SzOID_CP_GOST_R3410EL       = "1.2.643.2.2.19"
	SzOID_CP_GOST_R3410_12_256  = "1.2.643.7.1.1.1.1"
	SzOID_CP_GOST_R3410_12_512  = "1.2.643.7.1.1.1.2"
	SzOID_CP_DH_EX              = "1.2.643.2.2.99"
	SzOID_CP_DH_EL              = "1.2.643.2.2.98"
	SzOID_CP_DH_12_256          = "1.2.643.7.1.1.6.1"
	SzOID_CP_DH_12_512          = "1.2.643.7.1.1.6.2"
	SzOID_CP_GOST_R3410_94_ESDH = "1.2.643.2.2.97"
	SzOID_CP_GOST_R3410_01_ESDH = "1.2.643.2.2.96"

	//CRYPT_SIGN_ALG_OID_GROUP_ID
	SzOID_CP_GOST_R3411_R3410        = "1.2.643.2.2.4"
	SzOID_CP_GOST_R3411_R3410EL      = "1.2.643.2.2.3"
	SzOID_CP_GOST_R3411_12_256_R3410 = "1.2.643.7.1.1.3.2"
	SzOID_CP_GOST_R3411_12_512_R3410 = "1.2.643.7.1.1.3.3"

	//CRYPT_ENHKEY_USAGE_OID_GROUP_ID
	SzOID_KP_TLS_PROXY           = "1.2.643.2.2.34.1"
	SzOID_KP_RA_CLIENT_AUTH      = "1.2.643.2.2.34.2"
	SzOID_KP_WEB_CONTENT_SIGNING = "1.2.643.2.2.34.3"
	SzOID_KP_RA_ADMINISTRATOR    = "1.2.643.2.2.34.4"
	SzOID_KP_RA_OPERATOR         = "1.2.643.2.2.34.5"

	//HMAC algorithms
	SzOID_CP_GOST_R3411_94_HMAC       = "1.2.643.2.2.10"
	SzOID_CP_GOST_R3411_2012_256_HMAC = "1.2.643.7.1.1.4.1"
	SzOID_CP_GOST_R3411_2012_512_HMAC = "1.2.643.7.1.1.4.2"

	//Qualified Certificate
	SzOID_OGRN   = "1.2.643.100.1"
	SzOID_OGRNIP = "1.2.643.100.5"
	SzOID_SNILS  = "1.2.643.100.3"
	SzOID_INN    = "1.2.643.3.131.1.1"

	//Signature tool class
	SzOID_SIGN_TOOL_KC1 = "1.2.643.100.113.1"
	SzOID_SIGN_TOOL_KC2 = "1.2.643.100.113.2"
	SzOID_SIGN_TOOL_KC3 = "1.2.643.100.113.3"
	SzOID_SIGN_TOOL_KB1 = "1.2.643.100.113.4"
	SzOID_SIGN_TOOL_KB2 = "1.2.643.100.113.5"
	SzOID_SIGN_TOOL_KA1 = "1.2.643.100.113.6"

	//CA tool class
	SzOID_CA_TOOL_KC1 = "1.2.643.100.114.1"
	SzOID_CA_TOOL_KC2 = "1.2.643.100.114.2"
	SzOID_CA_TOOL_KC3 = "1.2.643.100.114.3"
	SzOID_CA_TOOL_KB1 = "1.2.643.100.114.4"
	SzOID_CA_TOOL_KB2 = "1.2.643.100.114.5"
	SzOID_CA_TOOL_KA1 = "1.2.643.100.114.6"

	//Our well-known policy ID
	SzOID_CEP_BASE_PERSONAL = "1.2.643.2.2.38.1"
	SzOID_CEP_BASE_NETWORK  = "1.2.643.2.2.38.2"

	//OIDs for HASH
	SzOID_GostR3411_94_TestParamSet         = "1.2.643.2.2.30.0"
	SzOID_GostR3411_94_CryptoProParamSet    = "1.2.643.2.2.30.1" /* ГОСТ Р 34.11-94, параметры по умолчанию */
	SzOID_GostR3411_94_CryptoPro_B_ParamSet = "1.2.643.2.2.30.2"
	SzOID_GostR3411_94_CryptoPro_C_ParamSet = "1.2.643.2.2.30.3"
	SzOID_GostR3411_94_CryptoPro_D_ParamSet = "1.2.643.2.2.30.4"

	//OIDs for Crypt
	SzOID_Gost28147_89_TestParamSet                 = "1.2.643.2.2.31.0"
	SzOID_Gost28147_89_CryptoPro_A_ParamSet         = "1.2.643.2.2.31.1" /* ГОСТ 28147-89, параметры по умолчанию */
	SzOID_Gost28147_89_CryptoPro_B_ParamSet         = "1.2.643.2.2.31.2" /* ГОСТ 28147-89, параметры шифрования 1 */
	SzOID_Gost28147_89_CryptoPro_C_ParamSet         = "1.2.643.2.2.31.3" /* ГОСТ 28147-89, параметры шифрования 2 */
	SzOID_Gost28147_89_CryptoPro_D_ParamSet         = "1.2.643.2.2.31.4" /* ГОСТ 28147-89, параметры шифрования 3 */
	SzOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = "1.2.643.2.2.31.5" /* ГОСТ 28147-89, параметры Оскар 1.1 */
	SzOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = "1.2.643.2.2.31.6" /* ГОСТ 28147-89, параметры Оскар 1.0 */
	SzOID_Gost28147_89_CryptoPro_RIC_1_ParamSet     = "1.2.643.2.2.31.7" /* ГОСТ 28147-89, параметры РИК 1 */

	SzOID_Gost28147_89_TC26_A_ParamSet = "1.2.643.2.2.31.12" /* ГОСТ 28147-89, параметры шифрования TC26 2 */
	SzOID_Gost28147_89_TC26_B_ParamSet = "1.2.643.2.2.31.13" /* ГОСТ 28147-89, параметры шифрования TC26 1 */
	SzOID_Gost28147_89_TC26_C_ParamSet = "1.2.643.2.2.31.14" /* ГОСТ 28147-89, параметры шифрования TC26 3 */
	SzOID_Gost28147_89_TC26_D_ParamSet = "1.2.643.2.2.31.15" /* ГОСТ 28147-89, параметры шифрования TC26 4 */
	SzOID_Gost28147_89_TC26_E_ParamSet = "1.2.643.2.2.31.16" /* ГОСТ 28147-89, параметры шифрования TC26 5 */
	SzOID_Gost28147_89_TC26_F_ParamSet = "1.2.643.2.2.31.17" /* ГОСТ 28147-89, параметры шифрования TC26 6 */

	SzOID_Gost28147_89_TC26_Z_ParamSet = "1.2.643.7.1.2.5.1.1" /* ГОСТ 28147-89, параметры шифрования ТС26 Z */

	//OID for Signature 1024
	SzOID_GostR3410_94_CryptoPro_A_ParamSet = "1.2.643.2.2.32.2" /*VerbaO*/
	SzOID_GostR3410_94_CryptoPro_B_ParamSet = "1.2.643.2.2.32.3"
	SzOID_GostR3410_94_CryptoPro_C_ParamSet = "1.2.643.2.2.32.4"
	SzOID_GostR3410_94_CryptoPro_D_ParamSet = "1.2.643.2.2.32.5"

	//OID for Signature 512
	SzOID_GostR3410_94_TestParamSet = "1.2.643.2.2.32.0" /*Test*/

	// OID for DH 1024
	SzOID_GostR3410_94_CryptoPro_XchA_ParamSet = "1.2.643.2.2.33.1"
	SzOID_GostR3410_94_CryptoPro_XchB_ParamSet = "1.2.643.2.2.33.2"
	SzOID_GostR3410_94_CryptoPro_XchC_ParamSet = "1.2.643.2.2.33.3"

	//OID for EC signature
	SzOID_GostR3410_2001_TestParamSet         = "1.2.643.2.2.35.0" /* ГОСТ Р 34.10 256 бит, тестовые параметры */
	SzOID_GostR3410_2001_CryptoPro_A_ParamSet = "1.2.643.2.2.35.1" /* ГОСТ Р 34.10 256 бит, параметры по умолчанию */
	SzOID_GostR3410_2001_CryptoPro_B_ParamSet = "1.2.643.2.2.35.2" /* ГОСТ Р 34.10 256 бит, параметры Оскар 2.x */
	SzOID_GostR3410_2001_CryptoPro_C_ParamSet = "1.2.643.2.2.35.3" /* ГОСТ Р 34.10 256 бит, параметры подписи 1 */

	SzOID_tc26_gost_3410_12_256_paramSetA = "1.2.643.7.1.2.1.1.1" /* ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор A */
	SzOID_tc26_gost_3410_12_256_paramSetB = "1.2.643.7.1.2.1.1.2" /* ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор B */
	SzOID_tc26_gost_3410_12_256_paramSetC = "1.2.643.7.1.2.1.1.3" /* ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор C */
	SzOID_tc26_gost_3410_12_256_paramSetD = "1.2.643.7.1.2.1.1.4" /* ГОСТ Р 34.10-2012, 256 бит, параметры ТК-26, набор D */

	SzOID_tc26_gost_3410_12_512_paramSetA = "1.2.643.7.1.2.1.2.1" /* ГОСТ Р 34.10-2012, 512 бит, параметры по умолчанию */
	SzOID_tc26_gost_3410_12_512_paramSetB = "1.2.643.7.1.2.1.2.2" /* ГОСТ Р 34.10-2012, 512 бит, параметры ТК-26, набор B */
	SzOID_tc26_gost_3410_12_512_paramSetC = "1.2.643.7.1.2.1.2.3" /* ГОСТ Р 34.10-2012, 512 бит, параметры ТК-26, набор С */

	//OID for EC DH
	SzOID_GostR3410_2001_CryptoPro_XchA_ParamSet = "1.2.643.2.2.36.0" /* ГОСТ Р 34.10 256 бит, параметры обмена по умолчанию */
	SzOID_GostR3410_2001_CryptoPro_XchB_ParamSet = "1.2.643.2.2.36.1" /* ГОСТ Р 34.10 256 бит, параметры обмена 1 */

	//OIDs for private key container extensions
	//Расширения контейнера. Поддерживаются начиная с CSP 3.6
	SzOID_CryptoPro_private_keys_extension_intermediate_store                         = "1.2.643.2.2.37.3.1"
	SzOID_CryptoPro_private_keys_extension_signature_trust_store                      = "1.2.643.2.2.37.3.2"
	SzOID_CryptoPro_private_keys_extension_exchange_trust_store                       = "1.2.643.2.2.37.3.3"
	SzOID_CryptoPro_private_keys_extension_container_friendly_name                    = "1.2.643.2.2.37.3.4"
	SzOID_CryptoPro_private_keys_extension_container_key_usage_period                 = "1.2.643.2.2.37.3.5"
	SzOID_CryptoPro_private_keys_extension_container_uec_symmetric_key_derive_counter = "1.2.643.2.2.37.3.6"

	SzOID_CryptoPro_private_keys_extension_container_primary_key_properties   = "1.2.643.2.2.37.3.7"
	SzOID_CryptoPro_private_keys_extension_container_secondary_key_properties = "1.2.643.2.2.37.3.8"

	SzOID_CryptoPro_private_keys_extension_container_signature_key_usage_period     = "1.2.643.2.2.37.3.9"
	SzOID_CryptoPro_private_keys_extension_container_exchange_key_usage_period      = "1.2.643.2.2.37.3.10"
	SzOID_CryptoPro_private_keys_extension_container_key_time_validity_control_mode = "1.2.643.2.2.37.3.11"

	SzOID_CryptoPro_private_keys_extension_container_arandom_state = "1.2.643.2.2.37.3.13"

	//OIDs for certificate and CRL extensions
	//Метод сопоставления CRL с сертификатом издателя.
	SzOID_CryptoPro_extensions_certificate_and_crl_matching_technique = "1.2.643.2.2.49.1"
	//Средство электронной подписи владельца
	SzCPOID_SubjectSignTool = "1.2.643.100.111"
	//Средства электронной подписи и УЦ издателя
	SzCPOID_IssuerSignTool = "1.2.643.100.112"

	// OIDs for signing certificate attributes
	//Группа атрибутов для хранения идентификатора сертификата ключа подписи
	SzCPOID_RSA_SMIMEaaSigningCertificate   = "1.2.840.113549.1.9.16.2.12"
	SzCPOID_RSA_SMIMEaaSigningCertificateV2 = "1.2.840.113549.1.9.16.2.47"
	SzCPOID_RSA_SMIMEaaETSotherSigCert      = "1.2.840.113549.1.9.16.2.19"

	//  GUIDs for extending CryptEncodeObject/CryptDecodeObject functionality
	//   Набор уникальных идентификаторов, используемых для расширения функциональности
	//   функций  CryptEncodeObject/CryptDecodeObject
	SzCPGUID_RSA_SMIMEaaSigningCertificateEncode   = "{272ED084-4C55-42A9-AD88-A1502D9ED755}"
	SzCPGUID_RSA_SMIMEaaSigningCertificateV2Encode = "{42AB327A-BE56-4899-9B81-1BF2F3C5E154}"
	SzCPGUID_RSA_SMIMEaaETSotherSigCertEncode      = "{410F6306-0ADE-4485-80CC-462DEB3AD109}"
	SzCPGUID_PRIVATEKEY_USAGE_PERIOD_Encode        = "{E36FC6F5-4880-4CB7-BA51-1FCD92CA1453}"

	//  GUIDs for extending CertVerifyCertificateChainPolicy functionality
	//  Набор уникальных идентификаторов, используемых для расширения функциональности
	//  функции = CertVerifyCertificateChainPolicy

	CPCERT_CHAIN_POLICY_PRIVATEKEY_USAGE_PERIOD = "{C03D5610-26C8-4B6F-9549-245B5B3AB743}"
	CPCERT_CHAIN_POLICY_SIGNATURE               = "{B52FF66F-13A5-402C-B958-A3A6B5300FB6}"
	CPCERT_CHAIN_POLICY_TIMESTAMP_SIGNING       = "{AF74EE92-A059-492F-9B4B-EAD239B22A1B}"
	CPCERT_CHAIN_POLICY_OCSP_SIGNING            = "{A4CC781E-04E9-425C-AAFD-1D74DA8DFAF6}"
)
