package verificationsymmetrictest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/einride/protoc-gen-messageintegrity/internal/keypairtestutils"
	verificationsymmetric "github.com/einride/protoc-gen-messageintegrity/internal/verificationsymmetric"
	v1 "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"log"
	"os"
	"path"
	"testing"
)

func createECDSAKeyPair(keyID verificationsymmetric.KeyID, curve elliptic.Curve) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if curve == nil {
		curve = elliptic.P256()
	}
	keysPath := path.Join(home, verificationsymmetric.DefaultKeysDir)
	// Generate the ECDSA Key.
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey

	// Save the private key to a file.
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	privateKeyBlock := &pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	err = os.MkdirAll(keysPath, os.ModePerm)
	if err != nil {
		return err
	}
	fmt.Printf("creating key at %v\n", keysPath)
	privatePem, err := os.Create(path.Join(keysPath, fmt.Sprintf("message_integrity_%v_ecdsa_private.pem", keyID)))

	if err != nil {
		return err
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return err
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(path.Join(keysPath, fmt.Sprintf("message_integrity_%v_ecdsa_public.pem", keyID)))
	if err != nil {
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return err
	}
	return nil
}

func TestCreateECDSA(t *testing.T) {
	tests := []struct {
		keyID         verificationsymmetric.KeyID
		curve         elliptic.Curve
		expectedError string
	}{
		{keyID: "test_create_id_1", curve: elliptic.P256(), expectedError: ""},
		{keyID: "test_create_id_2", curve: elliptic.P256(), expectedError: ""},
		{keyID: "test_create_id_3", curve: elliptic.P256(), expectedError: ""},
	}

	for _, test := range tests {
		err := createECDSAKeyPair(test.keyID, test.curve)

		if err != nil && err.Error() != test.expectedError {
			t.Errorf("error actual error: %v, expectedError: %v", err, test.expectedError)
		}

		privKey, err := verificationsymmetric.FetchPrivateKeyECDSA(test.keyID)
		if err != nil {
			t.Errorf("failed to fetch private key: %v", err)
		}
		log.Printf("Case KeyID: %v\n", test.keyID)
		log.Printf("Private key: %v\n", privKey)

		pubKey, err := verificationsymmetric.FetchPublicKeyECDSA(test.keyID)
		if err != nil {
			t.Errorf("failed to fetch public key: %v", err)
		}

		log.Printf("Public key: %v\n", pubKey)
	}
}

func TestSignatureVerificationECDSA(t *testing.T) {
	tests := []struct {
		keyID         verificationsymmetric.KeyID
		message       verificationsymmetric.VerifiableMessage
		expectedValue bool
		expectedError string
	}{
		{
			keyID:         "test_verification_id_1",
			message:       &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0},
			expectedValue: true,
			expectedError: "",
		},
		{
			keyID:         "test_verification_id_1",
			message:       &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0},
			expectedValue: true,
			expectedError: "",
		},
		{
			keyID:         "test_verification_id_2",
			message:       &v1.SteeringCommandVerificationOption{},
			expectedValue: true,
			expectedError: "",
		},
		{
			keyID:         "test_verification_id_does_not_exist",
			message:       &v1.SteeringCommandVerificationOption{},
			expectedValue: false,
			expectedError: "signature behaviour required but signature not set",
		},
		{
			keyID:         "test_verification_id_1",
			message:       nil,
			expectedValue: false,
			expectedError: "message was nil",
		},
		{
			keyID:         "test_verification_id_1",
			message:       &v1.SteeringCommandVerification{SteeringAngle: 6.0},
			expectedValue: false,
			expectedError: "failed to find any message integrity signature field in proto",
		},
	}

	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		_ = keypairtestutils.SetupEcdsaKeyPair(test.keyID)

		fakeRand := bytes.NewReader([]byte("This is not random reader....................................................."))
		// Don't check error as we want to test robustness of ValidateHMAC.
		_ = verificationsymmetric.SignECDSA(test.message, test.keyID, fakeRand)
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		isValid, err := verificationsymmetric.ValidateECDSA(test.message, test.keyID)
		if err != nil && err.Error() != test.expectedError {
			t.Errorf("Error actual = %v, and expected = %v", err, test.expectedError)
		}
		if err == nil && test.expectedError != "" {
			t.Errorf("Error actual = nil, and expected = %v", test.expectedError)
		}
		if isValid != test.expectedValue {
			t.Errorf("isValid actual = %v , and expected = %v", isValid, test.expectedValue)
		}
	}
}

func TestSignatureVerificationModificationECDSA(t *testing.T) {
	tests := []struct {
		keyID           verificationsymmetric.KeyID
		message         verificationsymmetric.VerifiableMessage
		receivedMessage verificationsymmetric.VerifiableMessage
		expectedValue   bool
		expectedError   string
	}{
		{
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0},
			receivedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 6.0,
				Signature: []byte{30, 141, 218, 216, 180, 165, 1, 224, 183, 115, 195, 7, 47, 98, 8, 242, 198, 44,
					222, 16, 169, 42, 16, 127, 163, 60, 139, 126, 57, 140, 146, 240, 45, 159, 105, 87, 44, 59, 169},
			},
			expectedValue: false,
			expectedError: "",
		},
		{
			keyID:           "test_verification_id_1",
			message:         &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0},
			receivedMessage: &v1.SteeringCommandVerificationOption{},
			expectedValue:   false,
			expectedError:   "signature behaviour required but signature not set",
		},
		{
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{},
			receivedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 6.0,
				Signature: []byte{193, 79, 117, 42, 123, 201, 187, 110, 121, 202, 16, 121, 18, 1, 1, 53, 191, 7, 126,
					222, 101, 180, 241},
			},
			expectedValue: false,
			expectedError: "",
		},
		{
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0},
			receivedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 6.0,
				Signature: []byte{
					48, 69, 2, 33, 0, 225, 146, 64, 95, 181, 122, 104, 175, 166, 139, 147, 170, 242, 204, 105, 199, 121, 75, 61, 100, 100, 139, 169, 51, 194, 144, 57, 61, 104, 135, 9, 231, 2, 32, 59, 17, 32, 218, 82, 152, 137, 161, 208, 201, 231, 180, 70, 29, 57, 54, 84, 169, 110, 23, 60, 176, 82, 182, 153, 16, 161, 72, 12, 20, 43, 248,
				},
			},
			expectedValue: true,
			expectedError: "",
		},
		{
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerification{SteeringAngle: 6.0},
			receivedMessage: &v1.SteeringCommandVerification{
				SteeringAngle: 6.0,
				Signature: []byte{193, 79, 117, 42, 123, 201, 187, 110, 121, 202, 16, 121, 18, 1, 1, 53, 191, 7, 126,
					222, 101, 180, 241},
			},
			expectedValue: false,
			expectedError: "failed to find any message integrity signature field in proto",
		},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)

		fakeRand := bytes.NewReader([]byte("This is not random reader....................................................."))
		// Don't check error as we want to test robustness of ValidateHMAC.
		_ = verificationsymmetric.SignECDSA(test.message, test.keyID, fakeRand)
		if test.receivedMessage != nil {
			log.Printf("Signature of Received Message: %v", test.receivedMessage.GetSignature())
		}
		isValid, err := verificationsymmetric.ValidateECDSA(test.receivedMessage, test.keyID)
		if err != nil && err.Error() != test.expectedError {
			t.Errorf("Error actual = %v, and expected = %v", err, test.expectedError)
		}
		if err == nil && test.expectedError != "" {
			t.Errorf("Error actual = nil, and expected = %v", test.expectedError)
		}
		if isValid != test.expectedValue {
			t.Errorf("sig: %v,\n ex sig:%v\n Error actual isValid: %v, expectedValue: %v for message: %v receivedMessge: %v",
				test.message.GetSignature(), test.receivedMessage.GetSignature(), isValid, test.expectedValue, test.message, test.receivedMessage)
		}
	}
}
