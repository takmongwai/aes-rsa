package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	AES128  = 16
	AES192  = 24
	AES256  = 32
	RSA768  = 768
	RSA1024 = 1024
	RSA2048 = 2048
)

type ARCrypto struct {
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

func NewArCrypto(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *ARCrypto {
	return &ARCrypto{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

// 检查密钥对长度
func (ar *ARCrypto) checkRSAKeySize() (err error) {
	ppl := ar.PublicKey.N.BitLen()
	prl := ar.PrivateKey.N.BitLen()
	c := func(m string, l int) error {
		switch l {
		case RSA768:
		case RSA1024:
		case RSA2048:
		default:
			return errors.New(fmt.Sprintf("RSA %s key size %d don't support.", m, l))
		}
		return nil
	}

	if err = c("public", ppl); err != nil {
		return
	}

	if err = c("private", prl); err != nil {
		return
	}

	return
}

// 加密和签名方法,RSA 密钥对长度支持 768,1024 和 2048 三个长度
// 参数:
// publicKey RSA公钥
// privateKey RSA私钥
// plain 需要要加密的明文
// 返回:
// cipherData 密文,密文数据结构:
// [数字签名][AES密钥密文][密文]
func (ar *ARCrypto) Encrypt(plain []byte) (finalCipher []byte, err error) {

	var chanCount = 2
	var errCh = make(chan error, chanCount) //用于同时生成密文和加密密钥

	var cipherData, cipherKey, sig []byte
	if err = ar.checkRSAKeySize(); err != nil {
		return
	}
	// 生成随机 AES 密码
	aesKey := make([]byte, AES128)
	if _, err = io.ReadFull(rand.Reader, aesKey); err != nil {
		return
	}
	// 用 AES 随机密码加密数据
	go func() {
		cipherData, err = AESEncrypt(aesKey, plain)
		errCh <- err
	}()

	// 用公钥加密 AES 随机密码,密文长度与公钥长度有关
	// AES密钥密文长度 = 证书公钥长度 / 8,如  RSA 公钥1024 位长度，则加密结果长度是 128
	go func() {
		cipherKey, err = RSAEncryptPKCS1v15(ar.PublicKey, aesKey)
		errCh <- err
	}()

	// 如果 AES 加密和密钥加密都没有错误
	for i := 0; i < chanCount; i++ {
		err = <-errCh
		if err != nil {
			return
		}
	}

	// 用私钥对 随机密码密文+数据密文 进行签名,签名长度 =
	var sigData []byte
	sigData = append(sigData, cipherKey...)
	sigData = append(sigData, cipherData...)
	// 对  cipherKey + cipherData 做数字签名,防止篡改
	if sig, err = RSASignPKCS1v15(ar.PrivateKey, sigData); err != nil {
		return
	}
	// 最终要返回对密文:
	finalCipher = append(finalCipher, sig...)        // 数字签名
	finalCipher = append(finalCipher, cipherKey...)  // AES密钥密文
	finalCipher = append(finalCipher, cipherData...) // 密文
	return
}

// 验签和解密
// 参数:
// publicKey  公钥
// privateKey 私钥
// cipherKey AES 密钥密文
// cipherData 密文
// sig 签名
func (ar *ARCrypto) Decrypt(data []byte) (plain []byte, err error) {

	var cipherData, cipherKey, sigData, sig, aesKey []byte

	// 需要先从密文中取出 数字签名,AES加密密钥密文,密文
	// 签名长度与私钥长度有关,签名长度 =  私钥长度 / 8
	sigLen := ar.PrivateKey.N.BitLen() / 8
	cipherKeyLen := ar.PublicKey.N.BitLen() / 8

	// 如果计算得到签名长度和AES密钥长度比密文长度大,密文肯定是非法
	if sigLen+cipherKeyLen >= len(data) {
		err = errors.New("CipherData error.")
		return
	}

	sig = data[:sigLen]
	cipherKey = data[sigLen : +sigLen+cipherKeyLen]
	cipherData = data[sigLen+cipherKeyLen:]
	sigData = data[sigLen:]

	//分别取到 cipherData, cipherKey, sig 之后,需要先做签名,如果验签失败,则退出
	//用于验签的数据 = cipherKey + cipherData
	if err = RSAVerifyPKCS1v15(ar.PublicKey, sigData, sig); err != nil {
		return
	}

	//签名通过之后,需要对密钥密文做解密取明文
	if aesKey, err = RSADecryptPKCS1v15(ar.PrivateKey, cipherKey); err != nil {
		return
	}

	// 用 AES key 明文对密文进行解密,得到最终的明文
	if plain, err = AESDecrypt(aesKey, cipherData); err != nil {
		return
	}

	return
}

// 加密结果以 Base64 字符串表示
func (ar *ARCrypto) EncryptToString(plain []byte) (finalCipher string, err error) {
	var en []byte
	if en, err = ar.Encrypt(plain); err != nil {
		return
	}
	finalCipher = base64.StdEncoding.EncodeToString(en)
	return
}

// 以 Bas64 字符串作为输入的解密
func (ar *ARCrypto) DecryptString(dataB64 string) (plain []byte, err error) {
	var data []byte
	if data, err = base64.StdEncoding.DecodeString(dataB64); err != nil {
		return
	}
	return ar.Decrypt(data)
}
