package verificationsymmetric

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
)


// Retrieve a pem encode private key from a file.
func FetchPrivateKeyECDSA(keyID KeyID) (*ecdsa.PrivateKey, error) {
	fileName := fmt.Sprintf("message_integrity_%v_ecdsa_private.pem", keyID)
	keyBlock, err := FetchKeyBlock(fileName)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return parsedKey, err
}

// Retrieve a pem encode private key from a file.
func FetchPrivateKey(keyID KeyID) (*rsa.PrivateKey, error) {
	fileName := fmt.Sprintf("message_integrity_%v_private.pem", keyID)
	keyBlock, err := FetchKeyBlock(fileName)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return parsedKey, err
}

// Retrieve a pem encode public key from a file.
func FetchPublicKeyECDSA(keyID KeyID) (*ecdsa.PublicKey, error) {
	fileName := fmt.Sprintf("message_integrity_%v_ecdsa_public.pem", keyID)
	keyBlock, err := FetchKeyBlock(fileName)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	parsedECDSAKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("parsed public key was not RSA, others not supported")
	}
	return parsedECDSAKey, err
}

// Retrieve a pem encode public key from a file.
func FetchPublicKey(keyID KeyID) (*rsa.PublicKey, error) {
	fileName := fmt.Sprintf("message_integrity_%v_public.pem", keyID)
	keyBlock, err := FetchKeyBlock(fileName)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	parsedRSAKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parsed public key was not RSA, others not supported")
	}
	return parsedRSAKey, err
}

// Retrieve a pem encoded file.
func FetchKeyBlock(fileName string) (*pem.Block, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	keysPath := path.Join(home, "integrity-keys")
	key, err := ioutil.ReadFile(path.Join(keysPath, fileName))
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(key)
	return keyBlock, nil
}
