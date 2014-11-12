package crypto

import (
	"log"
	"testing"
)

func TestGenRSAKeyPem(t *testing.T) {
	publicKey, privateKey, err := GenRSAKeyPem(768)
	log.Println(publicKey, privateKey, err)
}
