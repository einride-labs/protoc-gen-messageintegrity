package keypairtestutils

import (
	"fmt"
	"github.com/einride/protoc-gen-messageintegrity/internal/verificationsymmetric"
	"io"
	"os"
	"path"
	"strings"
)

// Moves the RSA keypair for the corresponding keyID from the test-keys dir to the directory used by message-integrity
func SetupRsaKeyPair(keyID verificationsymmetric.KeyID) error {
	keyName := fmt.Sprintf("message_integrity_%v", keyID)
	return setupKeyPair(keyName)
}

// Moves the ECDSA keypair for the corresponding keyID from the test-keys dir to the directory used by message-integrity
func SetupEcdsaKeyPair(keyID verificationsymmetric.KeyID) error {
	keyName := fmt.Sprintf("message_integrity_%v_ecdsa", keyID)
	return setupKeyPair(keyName)
}
// Moves the keypair for the corresponding keyID from the test-keys dir to the directory used by message-integrity
func setupKeyPair(keyName string) error {
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
	// Cases where we aren't running verificationsymmetrictest.
	// We're running from the plugin folder.
	if strings.HasSuffix(pwd,"internal/messageintegrity") {
		srcTestKeysDir = "../verificationsymmetrictest/test-keys"
	}
	// We're running from the repo root.
	if strings.HasSuffix(pwd, "thesis-implicit-message-integrity") {
		srcTestKeysDir = path.Join(".", "internal/verificationsymmetrictest/test-keys")
	}
	dstTestKeysDir := path.Join(home, verificationsymmetric.DefaultKeysDir)
	_ = os.Mkdir(dstTestKeysDir, os.ModeDir)
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
