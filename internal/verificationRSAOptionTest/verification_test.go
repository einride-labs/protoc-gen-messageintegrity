package verificationoptionirsaTest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	verificationoption "github.com/einride/protoc-gen-messageintegrity/internal/verificationOption"
	verificationoptionrsa "github.com/einride/protoc-gen-messageintegrity/internal/verificationRSAOption"
	v1 "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"google.golang.org/protobuf/proto"
	"log"
	"os"
	"path"
	"testing"
)

func TestCreatePKCS1(t *testing.T) {
	tests := []struct {
		keyID         string
		length        int
		expectedError string
	}{
		{keyID: "test_id_1", length: 2048, expectedError: ""},
		{keyID: "test_id_2", length: 4096, expectedError: ""},
	}

	for _, test := range tests {
		err := createRSAKeyPair(test.keyID, test.length)

		if err != nil && err.Error() != test.expectedError {
			t.Errorf("error actual error: %v, expectedError: %v", err, test.expectedError)
		}

		privKey, err := verificationoptionrsa.FetchPrivateKey(test.keyID)
		if err != nil {
			t.Errorf("failed to fetch private key: %v", err)
		}
		log.Printf("Case KeyID: %v\n", test.keyID)
		log.Print(privKey)

		pubKey, err := verificationoptionrsa.FetchPublicKey(test.keyID)
		if err != nil {
			t.Errorf("failed to fetch public key: %v", err)
		}
		log.Println(pubKey)
	}

}

func TestParsePKCS1(t *testing.T) {
	tests := []struct {
		key_id        string
		length        int
		expectedError string
	}{
		{key_id: "test_id_1", length: 2048, expectedError: ""},
		{key_id: "test_id_2", length: 4096, expectedError: ""},
	}

	for _, test := range tests {
		err := createRSAKeyPair(test.key_id, test.length)

		if err != nil && err.Error() != test.expectedError {
			t.Errorf("error actual error: %v, expectedError: %v", err, test.expectedError)
		}
	}

}

func createRSAKeyPair(keyID string, length int) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	keysPath := path.Join(home, "integrity-keys")
	// Generate the RSA Key.
	privateKey, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey

	// Save the private key to a file.
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	err = os.MkdirAll(keysPath, os.ModePerm)
	if err != nil {
		return err
	}
	privatePem, err := os.Create(path.Join(keysPath, fmt.Sprintf("message_integrity_%v_private.pem", keyID)))

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
	publicPem, err := os.Create(path.Join(keysPath, fmt.Sprintf("message_integrity_%v_public.pem", keyID)))
	if err != nil {
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return err
	}
	return nil
}

func TestSigningRSA(t *testing.T) {
	tests := []struct {
		key                   []byte
		message               verificationoption.VerifiableMessage
		expectedSignedMessage verificationoption.VerifiableMessage
		isValid               bool
		expectedError         string
	}{
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, isValid: true, expectedError: ""},
		{key: nil, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, isValid: false, expectedError: "key was nil"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: nil, expectedSignedMessage: nil, isValid: true, expectedError: "message was nil"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerification{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerification{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, isValid: false, expectedError: "failed to find any message integrity signature field in proto"},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		err := verificationoption.SignProto(test.message, test.key)
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		if err != nil && err.Error() != test.expectedError {
			t.Errorf("Error actual = %v, and expected = %v", err, test.expectedError)
		}
		if err == nil && test.expectedError != "" {
			t.Errorf("Error actual = nil, and expected = %v", test.expectedError)
		}
		if proto.Equal(test.message, test.expectedSignedMessage) != test.isValid {
			t.Errorf("error actual signed message: %v expected signed message: %v to be valid: %v", test.message, test.expectedSignedMessage, test.isValid)
		}
	}
}

func TestSigning(t *testing.T) {
	tests := []struct {
		key                   []byte
		message               verificationoption.VerifiableMessage
		expectedSignedMessage verificationoption.VerifiableMessage
		isValid               bool
		expectedError         string
	}{
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, isValid: true, expectedError: ""},
		{key: nil, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, isValid: false, expectedError: "key was nil"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: nil, expectedSignedMessage: nil, isValid: true, expectedError: "message was nil"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerification{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerification{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, isValid: false, expectedError: "failed to find any message integrity signature field in proto"},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		err := verificationoption.SignProto(test.message, test.key)
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		if err != nil && err.Error() != test.expectedError {
			t.Errorf("Error actual = %v, and expected = %v", err, test.expectedError)
		}
		if err == nil && test.expectedError != "" {
			t.Errorf("Error actual = nil, and expected = %v", test.expectedError)
		}
		if proto.Equal(test.message, test.expectedSignedMessage) != test.isValid {
			t.Errorf("error actual signed message: %v expected signed message: %v to be valid: %v", test.message, test.expectedSignedMessage, test.isValid)
		}
	}
}

func TestSignatureVerification(t *testing.T) {
	tests := []struct {
		key           []byte
		message       verificationoption.VerifiableMessage
		expectedValue bool
		expectedError string
	}{
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0}, expectedValue: true, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedValue: true, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{}, expectedValue: true, expectedError: ""},
		{key: nil, message: &v1.SteeringCommandVerificationOption{}, expectedValue: false, expectedError: "key was nil"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: nil, expectedValue: false, expectedError: "message was nil"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerification{SteeringAngle: 6.0}, expectedValue: false, expectedError: "failed to find any message integrity signature field in proto"},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		// Don't check error as we want to test robustness of ValidateHMAC.
		_ = verificationoption.SignProto(test.message, test.key)
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		isValid, err := verificationoption.ValidateHMAC(test.message, test.key)
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

func TestSignatureVerificationModification(t *testing.T) {
	tests := []struct {
		key             []byte
		message         verificationoption.VerifiableMessage
		receivedMessage verificationoption.VerifiableMessage
		expectedValue   bool
		expectedError   string
	}{
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0}, receivedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, expectedValue: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, receivedMessage: &v1.SteeringCommandVerificationOption{}, expectedValue: false, expectedError: "signature behaviour required but signature not set"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{}, receivedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, expectedValue: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, receivedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, expectedValue: true, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerification{SteeringAngle: 6.0}, receivedMessage: &v1.SteeringCommandVerification{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, expectedValue: false, expectedError: "failed to find any message integrity signature field in proto"},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		// Don't check error as we want to test robustness of ValidateHMAC.
		_ = verificationoption.SignProto(test.message, test.key)
		if test.receivedMessage != nil {
			log.Printf("Signature of Received Message: %v", test.receivedMessage.GetSignature())
		}
		isValid, err := verificationoption.ValidateHMAC(test.receivedMessage, test.key)
		if err != nil && err.Error() != test.expectedError {
			t.Errorf("Error actual = %v, and expected = %v", err, test.expectedError)
		}
		if err == nil && test.expectedError != "" {
			t.Errorf("Error actual = nil, and expected = %v", test.expectedError)
		}
		if isValid != test.expectedValue {
			t.Errorf("Error actual isValid: %v, expectedValue: %v for message: %v receivedMessge: %v", isValid, test.expectedValue, test.message, test.receivedMessage)
		}
	}

}
