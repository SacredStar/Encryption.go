package main

import (
	"GostCrypto/GostCrypto"
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
	var hProvHandle windows.Handle
	if err := windows.CryptAcquireContext(&hProvHandle, nil, nil, 80, windows.CRYPT_VERIFYCONTEXT); err != nil {
		fmt.Println(err.Error())
	}
	str := []byte("hello")
	data, err := GostCrypto.CreateHashFromData(hProvHandle, GostCrypto.CALG_GR3411_2012_256, &str[0], 5)
	if err != nil {
		fmt.Println("error")
	}
	fmt.Printf("%X", data)
	//fmt.Printf("%s", hash)
	/*
		GostCrypto.GetProviderParam(hProvhandle)
		providers := GostCrypto.EnumProviders()
		for provider := range providers {
			fmt.Printf("%s\n", &provider)
		}*/
}
