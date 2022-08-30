package main

import (
	"EncryptionPlugin/GostCrypto"
	"fmt"
	"golang.org/x/sys/windows"
)

/*
CryptAcquireContext(
        &hProv,
        NULL,
        NULL,
        PROV_GOST_2012_256,
        CRYPT_VERIFYCONTEXT))

*/

func main() {
	var hProvhandle windows.Handle = 0
	if err := windows.CryptAcquireContext(&hProvhandle, nil, nil, 80, windows.CRYPT_VERIFYCONTEXT); err != nil {
		fmt.Println(err.Error())
	}

	GostCrypto.GetProviderParam(hProvhandle)
	providers := GostCrypto.EnumProviders()
	for provider := range providers {
		fmt.Printf("%s\n", &provider)
	}
}
