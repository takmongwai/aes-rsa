package crypto

import (
	"testing"
)

func TestGenRSAKeyPem(t *testing.T) {
	publicKey, privateKey, err := GenRSAKeyPem(768)
	if err != nil {
		t.Fatal(err)
	}
	pk, prk, err := ParseRSAKeyFromPem([]byte(publicKey), []byte(privateKey))
	if err != nil {
		t.Fatal(err)
	}

	en, err := RSAEncryptPKCS1v15(pk, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	dn, err := RSADecryptPKCS1v15(prk, en)
	if err != nil {
		t.Fatal(err)
	}
	if string(dn) != "hello" {
		t.Fail()
	}
}
