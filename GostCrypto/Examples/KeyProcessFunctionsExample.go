package Examples

import (
	"fmt"
	"github.com/SacredStar/Encryption.go/GostCrypto"
	win32 "github.com/SacredStar/Encryption.go/GostCrypto/Win32GoFunctions"
	"syscall"
)

//--------------------------------------------------------------------
// Пример создания ключевого контейнера с именем по умолчанию.
//В контейнере созданиются два ключа (ключ обмена и ключ подписи).

func KeyGenExample() (err error) {
	//Создание ключевой пары
	//Задается имя ключевого контейнера

	fmt.Println("Функция-пример создания ключевого окнтейнера.")
	Container, err := syscall.UTF16PtrFromString("user")
	if err != nil {
		fmt.Printf("error get ptr from string")
		return err
	}
	gost, err := GostCrypto.NewGostCrypto(Container, nil, win32.ProvGost2012_512, 0)
	if err != nil {
		gost, err = GostCrypto.NewGostCrypto(Container, nil, win32.ProvGost2012, win32.CRYPT_NEWKEYSET)
		if err != nil {
			return err
		}
	}

	// Криптографический контекст с ключевым контейнером доступен. Получение
	// имени ключевого контейнера.
	var dwUserNameLen uint32
	if err = win32.CryptGetProvParam(*gost.GetPtrToProviderHandle(), win32.PP_CONTAINER, nil, &dwUserNameLen, 0); err != nil {
		fmt.Printf("error CryptGetProvParam:%s\n", err.Error())
		return nil
	}
	pszUserName := make([]byte, dwUserNameLen)
	if err = win32.CryptGetProvParam(*gost.GetPtrToProviderHandle(), win32.PP_CONTAINER, &pszUserName[0], &dwUserNameLen, 0); err != nil {
		fmt.Printf("error CryptGetProvParam:%s\n", err.Error())
		return nil
	}
	fmt.Printf("Имя полученного контейнера:%s\n", pszUserName)

	var hKey win32.Handle
	if err = win32.CryptGetUserKey(*gost.GetPtrToProviderHandle(), win32.AT_SIGNATURE, hKey); err != nil {
		if err == syscall.Errno(win32.NTE_NO_KEY) {
			// Создание подписанной ключевой пары.
			fmt.Println("The signature key does not exist.")
			fmt.Println("Creating a signature key pair...")
			if err = win32.CryptGenKey(*gost.GetPtrToProviderHandle(), win32.AT_SIGNATURE, 0, &hKey); err != nil {
				fmt.Printf("error CryptGenKey:%s\n", err.Error())
				return nil
			}
		}
	}

	// Получение ключа обмена: AT_KEYEXCHANGE
	if err = win32.CryptGetUserKey(*gost.GetPtrToProviderHandle(), win32.AT_SIGNATURE, hKey); err != nil {
		//printf("No exchange key is available.\n");
		fmt.Printf("error CryptGetUserKey:%s\n", err.Error())
	}
	fmt.Printf("Функция-пример создания ключевого контейнера завершена...\n\n")
	return nil
}
