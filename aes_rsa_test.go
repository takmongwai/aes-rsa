package crypto

import (
	"log"
	"testing"
	"time"
)

var plain = []byte(`>>>I need to validate a google id_token and one step involves to check the token signature.<<<`)

var sigData = []byte("abcdefg1234567890")

// AES 加密测试
func TestAES(t *testing.T) {

	key := []byte("123456789012345678901234567890AA")
	log.Println("动态 IV 测试")
	log.Println("原始明文:", string(plain))

	en, err := AESEncrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
  // log.Println("密文:", en)

	pn, err := AESDecrypt(key, en)

	if err != nil {
		t.Fatal(err)
	}

	log.Println("解密明文:", string(pn))

	if string(plain) != string(pn) {
		t.Fatal("解密结果与明文不符")
	}
}

// 固定 IV AES 加密测试
func TestAESFixedIV(t *testing.T) {
	key := []byte("123456789012345678901234567890AA")
	iv := []byte("1234567890123456")

	log.Println("固定 IV 测试")
	log.Println("原始明文:", string(plain))

	en, err := AESEncryptFixedIV(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
  // log.Println("密文:", en)

	pn, err := AESDecryptFixedIV(key, iv, en)

	if err != nil {
		t.Fatal(err)
	}

	log.Println("解密明文:", string(pn))

	if string(plain) != string(pn) {
		t.Fatal("解密结果与明文不符")
	}

}

// RSA 测试

func TestRSA(t *testing.T) {
	publicKey, privateKey, err := GenRSAKey(2048)

	if err != nil {
		t.Fatal(err)
	}

	en, err := RSAEncryptPKCS1v15(publicKey, plain)
	if err != nil {
		t.Fatal(err)
	}
  // log.Println("RSA 加密密文", en)

	pn, err := RSADecryptPKCS1v15(privateKey, en)

	if err != nil {
		t.Fatal(err)
	}
	log.Println("RSA 解密明文", string(pn))

	if string(plain) != string(pn) {
		t.Fatal("解密结果与明文不符")
	}

	sd, err := RSASignPKCS1v15(privateKey, sigData)

	if err != nil {
		t.Fatal(err)
	}

	log.Println("签名结果", sd)

	err = RSAVerifyPKCS1v15(publicKey, sigData, sd)
	if err != nil {
		log.Println("验签失败")
		t.Fatal(err)
	}

}

func TestAREncrypt(t *testing.T) {
	publicKey, privateKey, _ := GenRSAKey(1024)

	ar := NewArCrypto(publicKey, privateKey)

	count := 10
	s := time.Now()
	for i := 0; i < count; i++ {

		en, err := ar.Encrypt(plain)

		if err != nil {
			t.Fatal(err)
		}

		pn, err := ar.Decrypt(en)
		if err != nil {
			t.Fatal(err)
		}

		if string(plain) != string(pn) {
			t.Fatal("解密结果与明文不符")
		}
	}

	log.Printf("测试 %d 次加密/解密,耗时: %s \n", count, time.Now().Sub(s))

}
