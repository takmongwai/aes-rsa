package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

// 从 publicKey,private Pem 中还原密钥
func ParseRSAKeyFromPem(pubByte, privByte []byte) (*rsa.PublicKey, *rsa.PrivateKey, error) {

	block, _ := pem.Decode(pubByte)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse RSA public key: %s", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)

	if !ok {
		return nil, nil, fmt.Errorf("Value returned from ParsePKIXPublicKey was not an RSA public key")
	}

	block, _ = pem.Decode(privByte)
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse RSA private key: %s", err)
	}

	return rsaPub, priv, nil
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

	publicKeyDer, err := x509.MarshalPKIXPublicKey(publicKey)
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
