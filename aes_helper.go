package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// AESEncrypt 加密函数,使用动态 IV
// 加密密文的前 N 字节为动态生成的 IV
func AESEncrypt(key, plain []byte) ([]byte, error) {

	if err := checkAESKeyLen(key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	b := base64.StdEncoding.EncodeToString(plain)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

// AESAESDecrypt 解密函数
// 加密密文的前 N 字节为动态生成的 IV
func AESDecrypt(key, cipherText []byte) ([]byte, error) {
	if err := checkAESKeyLen(key); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := cipherText[:aes.BlockSize]

	cipherText = cipherText[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)

	cfb.XORKeyStream(cipherText, cipherText)

	data, err := base64.StdEncoding.DecodeString(string(cipherText))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// 检查密钥长度
func checkAESKeyLen(key []byte) error {
	switch len(key) {
	case AES128:
	case AES192:
	case AES256:
		return nil
	default:
		return errors.New("AES Key Size Error.")
	}
	return nil
}
