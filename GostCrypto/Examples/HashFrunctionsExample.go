package Examples

import (
	"fmt"
	"github.com/SacredStar/Encryption.go/GostCrypto"
	win32 "github.com/SacredStar/Encryption.go/GostCrypto/Win32GoFunctions"
	"os"
	"syscall"
)

// CreateHashExample Пример на создание хеша
func CreateHashExample() {
	//--------------------------------------------------------------------
	// Пример создания хэша из содержимого файла. Имя файла задается в
	// командной строке и является обязательным параметром.
	//--------------------------------------------------------------------
	fmt.Println("Функция-пример создания хеша")
	//Вызываем контекст провайдера используя высокоуровневую функцию библиотеки, она соответствует CryptAccquireContext
	//Далее опущены адекватные проверки функций DestroyHash,ReleaseContext, в проде должны быть обработаны.
	gost, err := GostCrypto.NewGostCrypto(nil, nil, win32.ProvGost2012, win32.CRYPT_VERIFYCONTEXT)
	if err != nil {
		fmt.Printf("Error Accuiqre context")
		return
	}
	//Создадим аналог файла открытого в байтовом формате, для простоты можно использовать слайс байт
	file := []byte("Test Example")
	//--------------------------------------------------------------------
	// Создание пустого объекта функции хэширования.Так как функция принимает не указатель на провайдер, используем дереференс
	if err := win32.CryptCreateHash(*gost.GetPtrToProviderHandle(), win32.CALG_GR3411_2012_256, 0, gost.GetPtrToHashHandle()); err != nil {
		fmt.Println("ERROR:%s", err.Error())
		fmt.Printf("ERROR:%s", err.Error())
		if win32.CryptDestroyHash(*gost.GetPtrToHashHandle()) != nil {
			fmt.Printf("ERROR:%s\n", err.Error())
		}
		if win32.CryptReleaseContext(*gost.GetPtrToProviderHandle()) != nil {
			fmt.Printf("ERROR:%s", err.Error())
		}
		return
	}
	//--------------------------------------------------------------------
	// Чтение данных из файла и хэширование этих данных. Поскольку все win функции принимают внутри себя разные виды переменных, могут требоваться дополнительные преобразования
	// в частности, тут требуется приведение типов к *byte и uint32
	if err := win32.CryptHashData(*gost.GetPtrToHashHandle(), &file[0], uint32(len(file)), 0); err != nil {
		fmt.Printf("ERROR:%s", err.Error())
		if win32.CryptDestroyHash(*gost.GetPtrToHashHandle()) != nil {
			fmt.Printf("ERROR:%s\n", err.Error())
		}
		if win32.CryptReleaseContext(*gost.GetPtrToProviderHandle()) != nil {
			fmt.Printf("ERROR:%s", err.Error())
		}
		return
	}
	//--------------------------------------------------------------------
	// Получение параметра объекта функции хэширования. size - размер полученного хеш-значения в байтах.Устанавливается в зависимости от алгоритма.
	size := 32
	var resultHash = make([]byte, size)
	pdwDataLen := uint32(size)
	if err := win32.CryptGetHashParam(
		*gost.GetPtrToHashHandle(),
		win32.HP_HASHVAL,
		&resultHash[0],
		&pdwDataLen,
		0); err != nil {
		fmt.Printf("ERROR:%s", err.Error())
		if win32.CryptDestroyHash(*gost.GetPtrToHashHandle()) != nil {
			fmt.Printf("ERROR:%s\n", err.Error())
		}
		if win32.CryptReleaseContext(*gost.GetPtrToProviderHandle()) != nil {
			fmt.Printf("ERROR:%s", err.Error())
		}
		return
	}

	fmt.Printf("Хеш равен:%X\n", resultHash)
	// Освобождаем ресурсы, можно использовать проверку в анонимной функции вызываемой defer. Такой пример будет в следующей функции-примере
	if err := win32.CryptDestroyHash(*gost.GetPtrToHashHandle()); err != nil {
		fmt.Printf("ERROR:%s\n", err.Error())
	}
	if err := win32.CryptReleaseContext(*gost.GetPtrToProviderHandle()); err != nil {
		fmt.Printf("ERROR:%s", err.Error())
	}
	fmt.Printf("Функция-пример создания завершена.\n\n")
}

// CreateSignExample Пример на подпись объекта функции хэширования и проверку подписи
func CreateSignExample() (err error) {
	fmt.Printf("Функция-пример создания подписи. Состоит из двух этапов. Создание подписи и её проверка.\n")
	pbBuffer := []byte("Data to be hashed and signed")
	dwBufferLen := len(pbBuffer)
	Container, err := syscall.UTF16PtrFromString("user")
	if err != nil {
		fmt.Printf("error get ptr from string")
		return err
	}
	//CryptAcquireContext
	gost, err := GostCrypto.NewGostCrypto(Container, nil, win32.ProvGost2012, 0)
	// Заранее освобождаем ресурсы при выходе из функции, следует использовать с осторожностью если у Вас глобальные объявления
	defer func() {
		if err := gost.ReleaseResources(); err != nil {
			panic(err)
		}
	}()

	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	// не забываем уничтожить хендлы...
	defer win32.CryptDestroyHash(*gost.GetPtrToHashHandle())
	defer win32.CryptReleaseContext(*gost.GetPtrToProviderHandle())
	// Получение открытого ключа подписи. Этот открытый ключ будет
	// использоваться получателем хэша для проверки подписи.
	// В случае, когда получатель имеет доступ к открытому ключю
	// отправителя с помощью сертификата, этот шаг не нужен.
	var phKey win32.Handle
	if err := win32.CryptGetUserKey(*gost.GetPtrToProviderHandle(), win32.AT_SIGNATURE, &phKey); err != nil {
		fmt.Printf("error CryptGetUserKey:%s\n", err.Error())
		return nil
	}
	//CryptGetUserKey(
	//        hProv,
	//        AT_SIGNATURE,
	//        &hKey))
	if err = win32.CryptGetUserKey(*gost.GetPtrToProviderHandle(), win32.AT_SIGNATURE, &phKey); err != nil {
		fmt.Printf("error CryptGetUserKey:%s\n", err.Error())
		return nil
	}
	// Экпорт открытого ключа. Здесь открытый ключ экспортируется в
	// PUBLICKEYBOLB для того, чтобы получатель подписанного хэша мог
	// проверить подпись. Этот BLOB может быть записан в файл и передан
	// другому пользователю.
	var dwBlobLen uint32
	if err = win32.CryptExportKey(phKey, 0, win32.PUBLICKEYBLOB, 0, nil, &dwBlobLen); err != nil {
		fmt.Printf("error CryptExportKey,get len Error:%s\n", err.Error())
		return nil
	}
	keyBlob := make([]byte, dwBlobLen)
	if err = win32.CryptExportKey(phKey, 0, win32.PUBLICKEYBLOB, 0, &keyBlob[0], &dwBlobLen); err != nil {
		fmt.Printf("error CryptExportKey,get key Error:%s\n", err.Error())
		return nil
	}

	// Создание объекта функции хэширования.
	err = win32.CryptCreateHash(*gost.GetPtrToProviderHandle(), win32.CALG_GR3411_2012_256, 0, gost.GetPtrToHashHandle())
	if err != nil {
		fmt.Printf("error CryptCreateHash Error:%s\n", err.Error())
		return nil
	}

	//Определение размера BLOBа и распределение памяти.
	//TODO:Check this
	var cbHash uint32
	if err = win32.CryptGetHashParam(*gost.GetPtrToHashHandle(), win32.HP_OID, nil, &cbHash, 0); err != nil {
		fmt.Printf("error CryptGetHashParam Error:%s\n", err.Error())
		return err
	}
	cbHash = 256
	var pbHash = make([]byte, cbHash)
	if err = win32.CryptGetHashParam(*gost.GetPtrToHashHandle(), win32.HP_OID, &pbHash[0], &cbHash, 0); err != nil {
		fmt.Printf("error CryptGetHashParam Error:%s\n", err.Error())
		return err
	}

	// Вычисление криптографического хэша буфера.
	if err = win32.CryptHashData(*gost.GetPtrToHashHandle(), &pbBuffer[0], uint32(dwBufferLen), 0); err != nil {
		fmt.Printf("error CryptHashData Error:%s\n", err.Error())
		return err
	}
	//Определение размера подписи и распределение памяти.
	var dwSigLen uint32

	if err = win32.CryptSignHash(*gost.GetPtrToHashHandle(), win32.AT_SIGNATURE, nil, 0, nil, &dwSigLen); err != nil {
		fmt.Printf("error CryptSignHash Error:%s\n", err.Error())
		return err
	}
	pbSignature := make([]byte, dwSigLen)

	if err = win32.CryptSignHash(*gost.GetPtrToHashHandle(), win32.AT_SIGNATURE, nil, 0, &pbSignature[0], &dwSigLen); err != nil {
		fmt.Printf("error CryptSignHash Error:%s\n", err.Error())
		return err
	}
	// Запись в файл
	file, err := os.Create("./SignatureHashFunctionExample.txt")
	if err != nil {
		fmt.Printf("error CreateFile Error:%s\n", err.Error())
		return err
	}

	file.Write(pbSignature)
	file.Close()
	fmt.Printf("Окончание первого этапа, подпись сформирована...\n")

	// Во второй части программы проверяется подпись.
	// Чаще всего проверка осуществляется в случае, когда различные
	// пользователи используют одну и ту же программу. Хэш, подпись,
	// а также PUBLICKEYBLOB могут быть прочитаны из файла, e-mail сообщения
	// или из другого источника.

	// Здесь используюся определенные ранее pbBuffer, pbSignature,
	// szDescription, pbKeyBlob и их длины.

	// Содержимое буфера pbBuffer представляет из себя некоторые
	// подписанные ранее данные.

	// Указатель szDescription на текст, описывающий данные, подписывается.
	// Это тот же самый текст описания, который был ранее передан
	// функции CryptSignHash.

	//--------------------------------------------------------------------
	// Получение откытого ключа пользователя, который создал цифровую подпись,
	// и импортирование его в CSP с помощью функции CryptImportKey. Она
	// возвращает дескриптор открытого ключа в hPubKey.
	fmt.Println("Начало второго этапа.")
	var hPubKey win32.Handle
	defer func() {
		if err := win32.CryptDestroyKey(hPubKey); err != nil {
			panic(err)
		}
	}()
	if err = win32.CryptImportKey(*gost.GetPtrToProviderHandle(), &keyBlob[0], dwBlobLen, 0, 0, &hPubKey); err != nil {
		fmt.Printf("Error CryptImportKey:%s", err.Error())
	}

	// Создание объекта функции хэширования.
	err = win32.CryptCreateHash(*gost.GetPtrToProviderHandle(), win32.CALG_GR3411_2012_256, 0, gost.GetPtrToHashHandle())
	if err != nil {
		fmt.Printf("error CryptCreateHash Error:%s\n", err.Error())
		return nil
	}
	//--------------------------------------------------------------------
	// Вычисление криптографического хэша буфера.
	if err = win32.CryptHashData(*gost.GetPtrToHashHandle(), &pbBuffer[0], uint32(dwBufferLen), 0); err != nil {
		fmt.Printf("error CryptHashData Error:%s\n", err.Error())
		return err
	}
	if err = win32.CryptVerifySignature(*gost.GetPtrToHashHandle(), &pbSignature[0], dwSigLen, hPubKey, nil, 0); err != nil {
		fmt.Printf("error CryptVerifySignature Error:%s\n", err.Error())
		return err
	} else {
		fmt.Printf("Функция-пример создания подписи звершила работу.Проверка подписи осуществилась успешно.\n\n")
	}

	return nil
}

// CreateDuplicateHashExample осуществляет хеширование строки, дублирование и добавление данных для хеширования.
func CreateDuplicateHashExample() (err error) {
	//--------------------------------------------------------------------
	// В данном примере осуществляется хэширование строки, дублирование
	// полученного хэша. Затем осуществляется хэширование дополнительных
	// данных при помощи оригинального и дублированного хэша.
	//--------------------------------------------------------------------
	fmt.Println("Функция-пример хеширования и дублирования хешей.")
	gost, err := GostCrypto.NewGostCrypto(nil, nil, win32.ProvGost2012, win32.CRYPT_VERIFYCONTEXT)
	if err != nil {
		fmt.Printf("error NewGostCrypto:%s", err.Error())
		return err
	}
	defer func() {
		if err := gost.ReleaseResources(); err != nil {
			panic(err)
		}
	}()
	//--------------------------------------------------------------------
	// Создание объекта функции хэширования.
	if err := win32.CryptCreateHash(*gost.GetPtrToProviderHandle(), win32.CALG_GR3411_2012_256, 0, gost.GetPtrToHashHandle()); err != nil {
		fmt.Printf("error CryptCreateHash:%s", err.Error())
		return err
	}
	//--------------------------------------------------------------------
	// Хэширование байтовой строки.
	data := []byte("Some Common Data")
	if err := win32.CryptHashData(*gost.GetPtrToHashHandle(), &data[0], uint32(len(data)), 0); err != nil {
		fmt.Printf("error CryptHashData:%s", err.Error())
		return err
	}

	//--------------------------------------------------------------------
	// Дублирование хэша.
	// Эта функция работает только в Windows 2000 и старше.
	var hDuplicateHash win32.Handle
	//Не забываем освободить ресурсы
	defer func() {
		if err := win32.CryptDestroyHash(hDuplicateHash); err != nil {
			panic(err)
		}
	}()
	if err := win32.CryptDuplicateHash(*gost.GetPtrToHashHandle(), nil, 0, &hDuplicateHash); err != nil {
		fmt.Printf("error CryptDuplicateHash:%s", err.Error())
		return err
	}
	//Phase 1 printing
	fmt.Printf("Phase1 Original :%x\n", GetAndPrintHash(*gost.GetPtrToHashHandle()))
	fmt.Printf("Phase1 Duplicate:%x\n", GetAndPrintHash(hDuplicateHash))
	//--------------------------------------------------------------------
	// Хэширование "Some Data" с оригинальным хэшем.
	SomeData := []byte("Some Data")
	if err := win32.CryptHashData(*gost.GetPtrToHashHandle(), &SomeData[0], uint32(len(SomeData)), 0); err != nil {
		fmt.Printf("error CryptHashData(Some Data):%s", err.Error())
		return err
	}
	//--------------------------------------------------------------------
	// Хэширование "Other Data" с дублированным хэшем.
	OtherData := []byte("Other Data")
	if err := win32.CryptHashData(hDuplicateHash, &OtherData[0], uint32(len(OtherData)), 0); err != nil {
		fmt.Printf("error CryptHashData(Other Data):%s", err.Error())
		return err
	}
	// Phase 2 printing
	fmt.Printf("Phase2 Original :%x\n", GetAndPrintHash(*gost.GetPtrToHashHandle()))
	fmt.Printf("Phase2 Duplicate:%x\n", GetAndPrintHash(hDuplicateHash))
	fmt.Printf("Функция-пример дублирования завершила работу.\n\n")
	return nil
}

// GetAndPrintHash всомогательная функция, для вывода полученного хеша
func GetAndPrintHash(hHash win32.Handle) (hash string) {
	// Иы спользуем дублирование, иначе при вызове GetHashParam с HP_HASHVAL объект хеширования закроется.
	var hTempHash win32.Handle
	//Не забываем освободить ресурсы
	defer func() {
		if err := win32.CryptDestroyHash(hTempHash); err != nil {
			panic(err)
		}
	}()

	if err := win32.CryptDuplicateHash(hHash, nil, 0, &hTempHash); err != nil {
		fmt.Printf("error CryptDuplicateHash:%s", err.Error())
		return ""
	}
	// Так как в примере используется ГОСТ 2012-256, в противном случае необходимо проделывать всю проверку
	size := 32
	var pbData = make([]byte, size)
	pdwDataLen := uint32(size)
	if err := win32.CryptGetHashParam(
		hTempHash,
		win32.HP_HASHVAL,
		&pbData[0],
		&pdwDataLen,
		0); err != nil {
		return ""
	}
	return string(pbData)
}
