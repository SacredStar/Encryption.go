package Examples

import (
	"fmt"
	"github.com/SacredStar/Encryption.go/GostCrypto"
	win32 "github.com/SacredStar/Encryption.go/GostCrypto/Win32GoFunctions"
	"syscall"
	"unsafe"
)

func EncryptDecryptMsgExample() {
	//--------------------------------------------------------------------
	// Пример кода для зашифрования данных и создания зашифрованного
	// сообщения при помощи функции CryptEncryptMessage.
	// Для функционирования данного кода необходимы:
	// - контейнер с ключом AT_KEYEXCHANGE в провайдере PROV_GOST_2012_256
	// - сертификат этого ключа, установленный в хранилище пользователя ("MY")
	// Объявление и инициализация переменных. Они получают указатель на
	// сообщение, которое будет зашифровано. В данном коде создается сообщение,
	// получается указатель на него.

	pbContent := string("Security is our business")
	cbContent := uint32(len(pbContent)) // Длина сообщения, включая конечный 0

	fmt.Printf("source message: %s\n", pbContent)
	fmt.Printf("message length: %d bytes \n", cbContent)

	// Получение дескриптора криптографического провайдера.
	gost, err := GostCrypto.NewGostCrypto(nil, nil, win32.ProvGost2012, win32.CRYPT_VERIFYCONTEXT)
	if err != nil {
		fmt.Println(fmt.Errorf("cryptographic context could not be acquired"))
	}
	fmt.Printf("CSP has been acquired. \n")

	// Открытие системного хранилища сертификатов.
	// Пока мы работаем с winapi, необходимо передавать указатель на стринги
	storename, err := GostCrypto.UTF16PtrFromString("My")
	if err != nil {
		fmt.Printf("Error while getting Ptr from string")
		return
	}
	hStoreHandle, err := win32.CertOpenSystemStore(*gost.GetPtrToProviderHandle(), storename)
	if err != nil {
		fmt.Println(fmt.Errorf("cant open system store:%s\n", storename))
	}

	// Получение указателя на сертификат получателя с помощью
	// функции GetRecipientCert.

	pRecipientCert := GetRecipientCert(hStoreHandle)

	if pRecipientCert == nil {
		fmt.Printf("\nNo certificate with a CERT_KEY_CONTEXT_PROP_ID \n")
		fmt.Printf("property and an AT_KEYEXCHANGE private key available. \n")
		fmt.Printf("While the message could be encrypted, in this case, \n")
		fmt.Printf("it could not be decrypted in this program. \n")
		fmt.Printf("For more information, see the documentation for \n")
		fmt.Printf("CrypteEncryptMessage and CryptDecryptMessage.\n\n")
		return
	}
	szDName, err := GetCertDName(&pRecipientCert.PCertInfo.Subject)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}
	fmt.Printf("A recipient's certificate has been acquired: %s\n", szDName)

	// Инициализация структуры CryptAlgorithmIdentifier с нулем.
	//var EncryptAlgorithm win32.CryptAlgorithmIdentifier
	//GostCrypto.MemSet(unsafe.Pointer(&EncryptAlgorithm), 0, unsafe.Sizeof(win32.CryptAlgorithmIdentifier{}))
	ptrObjID, err := GostCrypto.UTF16PtrFromString(win32.SzOID_CP_GOST_28147)
	if err != nil {
		fmt.Println("error converting string to ptr")
		return
	}
	//EncryptAlgorithm.ObjId = ptrObjID

	// Инициализация структуры CRYPT_ENCRYPT_MESSAGE_PARA.
	var EncryptParams win32.CryptEncryptMessagePara
	GostCrypto.MemSet(unsafe.Pointer(&EncryptParams), 0, unsafe.Sizeof(win32.CryptEncryptMessagePara{}))
	EncryptParams.CbSize = uint32(unsafe.Sizeof(win32.CryptEncryptMessagePara{}))
	EncryptParams.DwMsgEncodingType = win32.PKCS_7_ASN_ENCODING | win32.X509_ASN_ENCODING
	EncryptParams.ContentEncryptionAlgorithm.ObjId = (*byte)(unsafe.Pointer(ptrObjID))
	EncryptParams.HCryptProv = *gost.GetPtrToProviderHandle()
	//EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm
	EncryptParams.DwFlags = 0
	EncryptParams.DwInnerContentType = 0

	// Вызов функции CryptEncryptMessage.
	var cbEncryptedBlob uint32
	//TODO: strange thing, need to refactor
	var pRecipientCertSlice []win32.PCertContext
	pRecipientCertSlice = append(pRecipientCertSlice, pRecipientCert)
	var pbEncryptedBlob *byte
	//ptrbContent, _ := GostCrypto.UTF16PtrFromString(pbContent)
	pbContent1 := []byte("Security is our business")
	cbContent1 := uint32(len(pbContent)) // Длина сообщения, включая конечный 0
	//var EncBlob byte
	if err := win32.CryptEncryptMessage(&EncryptParams, 1, pRecipientCert, &pbContent1[0], cbContent1, nil, &cbEncryptedBlob); err != nil {
		fmt.Printf("error CryptEncryptMessage function 1st usage:%s", err.Error())
		return
	}
	fmt.Printf("The encrypted message is %d bytes. \n", cbEncryptedBlob)
	// Распределение памяти под возвращаемый BLOB.
	//var pbEncryptedBlob *byte
	// Повторный вызов функции CryptEncryptMessage для зашифрования содержимого.
	if err := win32.CryptEncryptMessage(&EncryptParams, 1, pRecipientCert, &pbContent1[0], cbContent1, pbEncryptedBlob, &cbEncryptedBlob); err != nil {
		fmt.Printf("error CryptEncryptMessage function 2nd usage - Encryption Failed")
		return
	}
	fmt.Printf("Encryption succeeded. \n")

	// Вызов функции DecryptMessage, код которой описан после main, для расшифрования сообщения.
	//	DecryptMessage(pbEncryptedBlob, cbEncryptedBlob);*/
}

// GetRecipientCert перечисляет сертификаты в хранилище и находит
// первый сертификат, обладающий ключем AT_EXCHANGE. Если сертификат
// сертификат найден, то возвращается указатель на него.
func GetRecipientCert(hCertStore win32.Handle) win32.PCertContext {
	bCertNotFind := true
	var dwSize uint32
	//var pKeyInfo win32.PCryptKeyProvInfo

	//PropId := win32.CERT_KEY_PROV_INFO_PROP_ID
	var hProv win32.Handle

	if hCertStore == 0 {
		fmt.Printf("CertStoreisEmpty\n")
		return nil
	}

	for {
		// Поиск сертификатов в хранилище до тех пор, пока не будет достигнут
		// конец хранилища, или сертификат с ключем AT_KEYEXCHANGE не будет найден.
		var MyEncodingType = win32.PKCS_7_ASN_ENCODING | win32.X509_ASN_ENCODING
		var pCertContext win32.PCertContext

		pCertContext, _ = win32.CertFindCertificateInStore(hCertStore, uint32(MyEncodingType), 0, win32.CERT_FIND_ANY, nil, nil)

		if pCertContext == nil {
			break
		}

		// Для простоты в этом коде реализован только поиск первого
		// вхождения ключа AT_KEYEXCHANGE. Во многих случаях, помимо
		// поиска типа ключа, осуществляется также поиск определенного
		// имени субъекта.

		// Однократный вызов функции CertGetCertificateContextProperty
		// для получения возврашенного размера структуры.
		if err := win32.CertGetCertificateContextProperty(pCertContext, win32.CERT_KEY_PROV_INFO_PROP_ID, nil, &dwSize); err != nil {
			fmt.Printf("Error getting key property.\n")
			return nil
		}
		//--------------------------------------------------------------
		// распределение памяти под возвращенную структуру(dwSize).
		var pKeyInfo win32.PCryptKeyProvInfo
		GostCrypto.MemSet(unsafe.Pointer(&pKeyInfo), 0, unsafe.Sizeof(win32.CryptKeyProvInfo{}))
		pKeyInfoPointer := unsafe.Pointer(&pKeyInfo)

		//--------------------------------------------------------------
		// Получение структуры информации о ключе.
		if err := win32.CertGetCertificateContextProperty(pCertContext, win32.CERT_KEY_PROV_INFO_PROP_ID, pKeyInfoPointer, &dwSize); err != nil {
			fmt.Println("the second call CertGetCertificateContextProperty failed")
			return nil
		}

		pKeyProvInfo := (*win32.CryptKeyProvInfo)(pKeyInfoPointer)
		//var ProvName string
		//tempProvName := windows.UTF16PtrToString(pKeyProvInfo.PwszProvName)
		//fmt.Println(tempProvName)

		//-------------------------------------------
		// Проверка члена dwKeySpec на расширенный ключ и типа провайдера
		var hKey win32.Handle
		//fmt.Printf(pKeyProvInfo.PwszProvName)
		if pKeyProvInfo.DwKeySpec == (uint32)(win32.AT_KEYEXCHANGE) {
			//-------------------------------------------
			//попробуем открыть провайдер
			fFreeProv := false
			var CryptProv win32.Handle
			if err := win32.CryptAcquireCertificatePrivateKey(pCertContext, win32.CRYPT_ACQUIRE_COMPARE_KEY_FLAG, nil, &CryptProv, &pKeyProvInfo.DwKeySpec, &fFreeProv); err != nil {
				DwKeySpecCertEnroll := pKeyProvInfo.DwKeySpec
				if err := win32.CryptGetUserKey(hProv, win32.CertEnrollParams(DwKeySpecCertEnroll), &hKey); err != nil {
					bCertNotFind = false
					if err := win32.CryptDestroyKey(hKey); err != nil {
						fmt.Printf("Error while destroing Key")
						return nil
					}
				}
			}
		}
		// TODO: check PcertContext
		if bCertNotFind && pCertContext != nil {
			return pCertContext
		}
	}
	return nil

} // Конец определения GetRecipientCert

func GetCertDName(pNameBlob win32.PcertNameBlob) (pszNameTemp string, err error) {
	//----------------------------------------------------------------------------
	// Получение имени из CERT_NAME_BLOB

	cbName, err := win32.CertNameToStr(win32.X509_ASN_ENCODING, pNameBlob, win32.CERT_X500_NAME_STR|win32.CERT_NAME_STR_NO_PLUS_FLAG, nil, 0)
	if err != nil {
		fmt.Printf("Error GetCertDname Function:error occured")
		return "", err
	}
	if cbName < 1 {
		fmt.Printf("Error GetCertDname Function: cbname less then 1 symbol")
		return "", fmt.Errorf("CbName less then 1 symbol")
	}
	temp1 := make([]uint16, cbName)

	cbName, err = win32.CertNameToStr(win32.X509_ASN_ENCODING, pNameBlob, win32.CERT_X500_NAME_STR|win32.CERT_NAME_STR_NO_PLUS_FLAG, &temp1[0], uint32(cbName))
	pszNameTemp = syscall.UTF16ToString(temp1)
	return pszNameTemp, nil
}
