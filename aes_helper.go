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

	var ciphertext []byte
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ct, err := AESEncryptFixedIV(key, iv, plain)
	if err != nil {
		return nil, err
	}
	ciphertext = append(ciphertext, iv...)
	ciphertext = append(ciphertext, ct...)
	return ciphertext, nil
}

// AESEncryptToString 动态 iv 加密 reutrn base64 chiphertext
func AESEncryptToString(key, plain []byte) (string, error) {
	ciphertext, err := AESEncrypt(key, plain)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// AESEncrypt 加密函数,使用固定 IV,密文不附带 IV 值
func AESEncryptFixedIV(key, iv, plain []byte) ([]byte, error) {
	if err := checkAESKeyLen(key); err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("Wrong iv size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	b := base64.StdEncoding.EncodeToString(plain)
	ciphertext := make([]byte, len(b))

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext, []byte(b))
	return ciphertext, nil
}

// AESEncryptWithFixIVToString 固定 iv 加密,返回 base64 密文
func AESEncryptFixedIVToString(key, iv, plain []byte) (string, error) {
	ciphertext, err := AESEncryptFixedIV(key, iv, plain)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// AESDecryptString decrypt from base64 ciphertext
func AESDecryptString(key []byte, ciphertext string) ([]byte, error) {
	cb, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return AESDecrypt(key, cb)
}

// AESAESDecrypt 解密函数
// 加密密文的前 N 字节为动态生成的 IV
func AESDecrypt(key, ciphertext []byte) ([]byte, error) {
	return AESDecryptFixedIV(key, ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:])
}

// AESDecryptFixedString 解密函数,密文不带 iv 需要明确指定
func AESDecryptFixedString(key, iv []byte, ciphertext string) ([]byte, error) {
	cb, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return AESDecryptFixedIV(key, iv, cb)
}

// AESDecryptFixed 解密函数,密文不带 iv,需要明确指明iv才能成功解密
func AESDecryptFixedIV(key, iv, ciphertext []byte) ([]byte, error) {
	if err := checkAESKeyLen(key); err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("Wrong iv size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBDecrypter(block, iv)

	cfb.XORKeyStream(ciphertext, ciphertext)

	data, err := base64.StdEncoding.DecodeString(string(ciphertext))
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
