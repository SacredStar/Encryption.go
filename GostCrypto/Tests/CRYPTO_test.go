package Tests

import (
	"bytes"
	"github.com/SacredStar/Encryption.go/GostCrypto"
	"github.com/SacredStar/Encryption.go/GostCrypto/Win32GoFunctions"
	"testing"
)

type CryptCreateHashTestStruct struct {
	algID         win32.AlgoID
	dataToHash    string
	expectedHash  []byte
	expectedError error
}

var hHashHandle win32.Handle

var CryptCreateHashTestSuites = []CryptCreateHashTestStruct{
	{
		algID:         win32.CALG_GR3411,
		dataToHash:    "LOGINPASSWORD",
		expectedHash:  []byte("E17D82BC6AD160E9E6EFF2708701E60691B27AD0BB8B5AA0A7A154B99EA38C9B"),
		expectedError: nil,
	},
	{
		algID:         win32.CALG_GR3411_2012_256,
		dataToHash:    "LOGINPASSWORD",
		expectedHash:  []byte("DBB97F1D652516613A37B71F9928DC51A33A3C9B1EE87B5609D2AB4674F80222"),
		expectedError: nil,
	},
	{
		algID:         win32.CALG_GR3411_2012_512,
		dataToHash:    "LOGINPASSWORD",
		expectedHash:  []byte("8F81F3C82DBC57D6765C4227F00808FB4D44B4C244F943AB734A41227A2D133FD431CE8B6DD8BCB9B28D74FD25C827CF633EE61435701463071D81A1CE0B90CD"),
		expectedError: nil,
	},
}

func TestCreateHashFromData(t *testing.T) {
	gost := GostCrypto.NewGostCrypto(win32.ProvGost2012, win32.CRYPT_VERIFYCONTEXT)
	for _, test := range CryptCreateHashTestSuites {
		hVal, err := gost.CreateHashFromData(test.algID, []byte(test.dataToHash))
		if err != test.expectedError {
			t.Errorf("Test down\n got err: %#v  \n want:%#v ", err, test.expectedError)
		}
		if bytes.Equal(hVal, test.expectedHash) {
			t.Errorf("Test Down \n got: %s \n want: %s", hVal, test.expectedHash)
		}
	}
}
