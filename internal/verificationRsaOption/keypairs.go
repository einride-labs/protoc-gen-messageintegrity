package verificationrsaoption

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

// Moves the keypair for the kedID from the test-keys dir to the directory used by message-integrity
func SetupKeyPair(keyID KeyID) error {
	home, err := os.UserHomeDir()
	if err != nil {
		// Assuming the tests are being run from the root of the repo.
		return err
	}
	srcTestKeysDir := path.Join(".", "test-keys")
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	// Cases where we aren't running verificationRSAOptionTest.
	// We're running from the plugin folder.
	if strings.HasSuffix(pwd,"internal/messageintegrity") {
		srcTestKeysDir = "../verificationRsaOptionTest/test-keys"
	}
	// We're running from the repo root.
	if strings.HasSuffix(pwd, "thesis-implicit-message-integrity") {
		srcTestKeysDir = path.Join(".", "internal/verificationRsaOptionTest/test-keys")
	}
	dstTestKeysDir := path.Join(home, DefaultKeysDir)
	_ = os.Mkdir(dstTestKeysDir, os.ModeDir)
	keyName := fmt.Sprintf("message_integrity_%v", keyID)
	publicKeyName := fmt.Sprintf("%v_public.pem", keyName)
	privateKeyName := fmt.Sprintf("%v_private.pem", keyName)

	srcPublicKeyPath := path.Join(srcTestKeysDir, publicKeyName)
	srcPrivateKeyPath := path.Join(srcTestKeysDir, privateKeyName)
	dstPublicKeyPath := path.Join(dstTestKeysDir, publicKeyName)
	dstPrivateKeyPath := path.Join(dstTestKeysDir, privateKeyName)

	if err := copyFile(srcPublicKeyPath, dstPublicKeyPath); err != nil {
		return err
	}
	if err := copyFile(srcPrivateKeyPath, dstPrivateKeyPath); err != nil {
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
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
