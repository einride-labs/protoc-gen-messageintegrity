package keypairTestUtils

import (
	"fmt"
	"github.com/einride/protoc-gen-messageintegrity/internal/verificationRsaOption"
	"io"
	"os"
	"path"
	"strings"
)

// Moves the keypair for the kedID from the test-keys dir to the directory used by message-integrity
func SetupKeyPair(keyID verificationrsaoption.KeyID) error {
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
	dstTestKeysDir := path.Join(home, verificationrsaoption.DefaultKeysDir)
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
