package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// 生成 RSA 密钥对
func GenRSAKey(keyLen int) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLen)

	if err != nil {
		return nil, nil, err
	}

	privateKey.Precompute()
	err = privateKey.Validate()
	if err != nil {
		return nil, nil, err
	}

	publicKey := privateKey.PublicKey
	return &publicKey, privateKey, nil
}

// 生成 RSA 密钥对 Pem
func GenRSAKeyPem(keyLen int) (string, string, error) {

	publicKey, privateKey, err := GenRSAKey(keyLen)

	if err != nil {
		return "", "", err
	}
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}

	privateKeyPem := string(pem.EncodeToMemory(&privateKeyBlock))

	publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))

	return publicKeyPem, privateKeyPem, nil
}

//
func RSAEncryptPKCS1v15(publicKey *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, msg)
}

//
func RSADecryptPKCS1v15(privateKey *rsa.PrivateKey, encryptd []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptd)
}

//
func RSASignPKCS1v15(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hashFunc, digest)
}

//
func RSAVerifyPKCS1v15(publicKey *rsa.PublicKey, data, sig []byte) error {
	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, hashFunc, digest, sig)
}
