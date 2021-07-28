package verificationsymmetrictest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/einride/protoc-gen-messageintegrity/internal/keypairtestutils"
	"github.com/einride/protoc-gen-messageintegrity/internal/verificationsymmetric"
	v1 "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"google.golang.org/protobuf/proto"
	"log"
	"os"
	"path"
	"testing"
)

func TestCreatePKCS1(t *testing.T) {
	tests := []struct {
		keyID         verificationsymmetric.KeyID
		length        int
		expectedError string
	}{
		{keyID: "test_create_id_1", length: 2048, expectedError: ""},
		{keyID: "test_create_id_2", length: 4096, expectedError: ""},
		{keyID: "test_create_id_3", length: 2048, expectedError: ""},
	}

	for _, test := range tests {
		err := createRSAKeyPair(test.keyID, test.length)

		if err != nil && err.Error() != test.expectedError {
			t.Errorf("error actual error: %v, expectedError: %v", err, test.expectedError)
		}

		privKey, err := verificationsymmetric.FetchPrivateKey(test.keyID)
		if err != nil {
			t.Errorf("failed to fetch private key: %v", err)
		}
		log.Printf("Case KeyID: %v\n", test.keyID)
		log.Printf("Private key: %v\n", privKey)

		pubKey, err := verificationsymmetric.FetchPublicKey(test.keyID)
		if err != nil {
			t.Errorf("failed to fetch public key: %v", err)
		}
		log.Printf("Public key: %v\n", pubKey)
	}
}

func TestParsePKCS1(t *testing.T) {
	tests := []struct {
		keyID         verificationsymmetric.KeyID
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
	}

}

func createRSAKeyPair(keyID verificationsymmetric.KeyID, length int) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	keysPath := path.Join(home, verificationsymmetric.DefaultKeysDir)
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
		keyID                 verificationsymmetric.KeyID
		message               verificationsymmetric.VerifiableMessage
		expectedSignedMessage verificationsymmetric.VerifiableMessage
		isValid               bool
		expectedError         string
	}{
		{
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 7.0},
			expectedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 7.0,
				Signature: []byte{126, 69, 22, 158, 44, 42, 166, 21, 27, 196, 34, 173, 196, 166, 239, 87, 87, 73, 134,
					154, 245, 145, 246, 227, 169, 230, 206, 97, 202, 27, 186, 68, 208, 255, 35, 143, 7, 62, 31, 75, 113,
					102, 39, 136, 114, 146, 196, 21, 215, 55, 64, 73, 231, 43, 201, 84, 23, 201, 100, 220, 29, 241, 28,
					114, 212, 217, 136, 94, 150, 101, 250, 171, 40, 173, 129, 133, 194, 73, 244, 242, 254, 18, 201, 58,
					56, 10, 149, 236, 160, 25, 153, 6, 66, 99, 120, 122, 121, 179, 24, 229, 142, 228, 240, 215, 249,
					212, 192, 196, 149, 72, 123, 113, 45, 90, 86, 211, 79, 215, 64, 206, 154, 88, 55, 156, 193, 159, 39,
					79, 163, 158, 209, 153, 235, 97, 1, 202, 93, 181, 140, 58, 182, 109, 88, 116, 45, 153, 223, 119, 74,
					133, 83, 187, 70, 243, 164, 209, 26, 60, 99, 47, 195, 118, 96, 24, 51, 89, 158, 131, 55, 228, 157,
					231, 4, 192, 164, 176, 72, 26, 190, 126, 118, 46, 174, 135, 55, 86, 82, 1, 52, 174, 231, 237, 47,
					39, 171, 4, 7, 144, 151, 154, 186, 14, 244, 246, 34, 17, 242, 155, 181, 145, 45, 233, 18, 158, 202,
					162, 252, 107, 7, 90, 190, 73, 2, 123, 239, 1, 113, 185, 51, 26, 108, 80, 236, 76, 170, 18, 93, 236,
					82, 217, 97, 194, 9, 160, 166, 225, 45, 39, 168, 142, 193, 184, 52, 169, 67, 175},
			},
			isValid:       true,
			expectedError: "",
		},
		{
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 7.0},
			expectedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 7.0,
				Signature: []byte{125, 69, 22, 158, 44, 42, 166, 21, 27, 196, 34, 173, 196, 166, 239, 87, 87, 73, 134,
					154, 245, 145, 246, 227, 169, 230, 206, 97, 202, 27, 186, 68, 208, 255, 35, 143, 7, 62, 31, 75, 113,
					102, 39, 136, 114, 146, 196, 21, 215, 55, 64, 73, 231, 43, 201, 84, 23, 201, 100, 220, 29, 241, 28,
					114, 212, 217, 136, 94, 150, 101, 250, 171, 40, 173, 129, 133, 194, 73, 244, 242, 254, 18, 201, 58,
					56, 10, 149, 236, 160, 25, 153, 6, 66, 99, 120, 122, 121, 179, 24, 229, 142, 228, 240, 215, 249,
					212, 192, 196, 149, 72, 123, 113, 45, 90, 86, 211, 79, 215, 64, 206, 154, 88, 55, 156, 193, 159, 39,
					79, 163, 158, 209, 153, 235, 97, 1, 202, 93, 181, 140, 58, 182, 109, 88, 116, 45, 153, 223, 119, 74,
					133, 83, 187, 70, 243, 164, 209, 26, 60, 99, 47, 195, 118, 96, 24, 51, 89, 158, 131, 55, 228, 157,
					231, 4, 192, 164, 176, 72, 26, 190, 126, 118, 46, 174, 135, 55, 86, 82, 1, 52, 174, 231, 237, 47,
					39, 171, 4, 7, 144, 151, 154, 186, 14, 244, 246, 34, 17, 242, 155, 181, 145, 45, 233, 18, 158, 202,
					162, 252, 107, 7, 90, 190, 73, 2, 123, 239, 1, 113, 185, 51, 26, 108, 80, 236, 76, 170, 18, 93, 236,
					82, 217, 97, 194, 9, 160, 166, 225, 45, 39, 168, 142, 193, 184, 52, 169, 67, 175},
			},
			isValid:       false,
			expectedError: "",
		},
		{
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 8.0},
			expectedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 8.0,
				Signature: []byte{193, 79, 117, 42, 123, 201, 187, 110, 121, 202, 16, 121, 18, 1, 1, 53, 191, 7, 126,
					46, 247, 224, 234, 187, 253, 168, 127, 252, 249, 96, 218, 173, 123, 79, 140, 142, 35, 216, 205, 14,
					24, 242, 175, 126, 95, 160, 191, 151, 49, 240, 200, 131, 187, 29, 201, 25, 85, 247, 106, 247, 42,
					99, 218, 163, 84, 66, 179, 181, 241, 27, 204, 191, 166, 97, 53, 115, 115, 67, 4, 197, 144, 44, 101,
					116, 15, 52, 156, 218, 55, 21, 184, 122, 142, 186, 130, 73, 214, 110, 103, 71, 221, 33, 157, 230,
					148, 79, 109, 100, 162, 219, 89, 213, 139, 148, 222, 82, 114, 104, 117, 136, 46, 195, 76, 26, 219,
					211, 95, 133, 109, 43, 217, 32, 215, 100, 92, 194, 211, 92, 97, 243, 82, 83, 191, 103, 60, 63, 120,
					242, 102, 114, 165, 143, 190, 195, 146, 62, 207, 88, 21, 215, 45, 231, 234, 216, 9, 112, 150, 83,
					224, 212, 120, 102, 164, 242, 202, 100, 100, 183, 236, 107, 114, 98, 224, 120, 89, 39, 82, 34, 115,
					239, 72, 201, 237, 155, 16, 104, 51, 2, 27, 215, 103, 239, 157, 186, 215, 35, 42, 219, 30, 98, 185,
					92, 126, 149, 118, 123, 60, 45, 98, 189, 183, 222, 250, 134, 130, 232, 83, 211, 210, 0, 231, 163,
					200, 190, 81, 172, 130, 158, 234, 103, 132, 146, 220, 252, 89, 236, 205, 106, 185, 145, 192, 93,
					222, 101, 180, 241},
			},
			isValid:       true,
			expectedError: "",
		},
		{
			keyID:   "test_verification_id_does_not_exist",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 8.0},
			expectedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 8.0,
				Signature: []byte{193, 79, 117, 42, 123, 201, 187, 110, 121, 202, 16, 121, 18, 1, 1, 53, 191, 7, 126,
					46, 247, 224, 234, 187, 253, 168, 127, 252, 249, 96, 218, 173, 123, 79, 140, 142, 35, 216, 205, 14,
					24, 242, 175, 126, 95, 160, 191, 151, 49, 240, 200, 131, 187, 29, 201, 25, 85, 247, 106, 247, 42,
					99, 218, 163, 84, 66, 179, 181, 241, 27, 204, 191, 166, 97, 53, 115, 115, 67, 4, 197, 144, 44, 101,
					116, 15, 52, 156, 218, 55, 21, 184, 122, 142, 186, 130, 73, 214, 110, 103, 71, 221, 33, 157, 230,
					148, 79, 109, 100, 162, 219, 89, 213, 139, 148, 222, 82, 114, 104, 117, 136, 46, 195, 76, 26, 219,
					211, 95, 133, 109, 43, 217, 32, 215, 100, 92, 194, 211, 92, 97, 243, 82, 83, 191, 103, 60, 63, 120,
					242, 102, 114, 165, 143, 190, 195, 146, 62, 207, 88, 21, 215, 45, 231, 234, 216, 9, 112, 150, 83,
					224, 212, 120, 102, 164, 242, 202, 100, 100, 183, 236, 107, 114, 98, 224, 120, 89, 39, 82, 34, 115,
					239, 72, 201, 237, 155, 16, 104, 51, 2, 27, 215, 103, 239, 157, 186, 215, 35, 42, 219, 30, 98, 185,
					92, 126, 149, 118, 123, 60, 45, 98, 189, 183, 222, 250, 134, 130, 232, 83, 211, 210, 0, 231, 163,
					200, 190, 81, 172, 130, 158, 234, 103, 132, 146, 220, 252, 89, 236, 205, 106, 185, 145, 192, 93,
					222, 101, 180, 241},
			},
			isValid:       false,
			expectedError: "private key not found for key: test_verification_id_does_not_exist",
		},
		{
			keyID:   "test_verification_id_2",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 8.0},
			expectedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 8.0,
				Signature: []byte{22, 137, 173, 91, 165, 19, 55, 16, 73, 124, 127, 88, 239, 61, 170, 197, 46, 126, 187,
					164, 183, 49, 65, 182, 43, 96, 1, 220, 136, 163, 193, 25, 84, 77, 68, 237, 109, 246, 154, 119, 211,
					71, 14, 115, 85, 23, 188, 125, 103, 158, 117, 29, 147, 114, 134, 180, 165, 217, 140, 94, 26, 198,
					173, 178, 179, 198, 244, 236, 87, 147, 213, 187, 224, 216, 215, 125, 16, 145, 113, 175, 198, 186,
					10, 88, 245, 168, 132, 221, 4, 87, 97, 212, 169, 129, 230, 30, 202, 89, 89, 19, 246, 114, 185, 212,
					131, 60, 79, 220, 104, 220, 165, 246, 161, 229, 100, 142, 125, 155, 81, 114, 138, 114, 132, 194, 47,
					65, 148, 68, 3, 15, 206, 14, 47, 8, 6, 208, 99, 164, 181, 248, 26, 85, 58, 232, 98, 103, 103, 176,
					238, 255, 123, 30, 34, 72, 23, 119, 194, 159, 90, 148, 30, 85, 45, 12, 90, 108, 224, 98, 20, 72, 51,
					98, 34, 233, 81, 37, 97, 215, 154, 24, 146, 206, 219, 126, 164, 229, 125, 165, 160, 83, 238, 27, 95,
					13, 53, 223, 97, 141, 207, 39, 123, 32, 43, 29, 134, 204, 0, 16, 248, 230, 216, 39, 222, 229, 141,
					47, 12, 156, 120, 180, 56, 13, 165, 61, 120, 159, 66, 64, 158, 180, 25, 130, 2, 17, 42, 216, 200,
					146, 224, 139, 65, 66, 239, 40, 193, 92, 187, 49, 145, 40, 173, 234, 154, 162, 8, 150, 239, 176,
					136, 67, 33, 118, 39, 218, 159, 249, 170, 218, 148, 52, 148, 77, 17, 171, 251, 232, 8, 73, 21, 198,
					106, 6, 15, 232, 246, 12, 31, 177, 169, 219, 108, 137, 124, 65, 191, 1, 31, 111, 103, 184, 110, 168,
					48, 88, 42, 41, 233, 129, 41, 69, 212, 193, 89, 162, 7, 227, 153, 139, 218, 49, 169, 162, 141, 17,
					104, 205, 176, 62, 152, 159, 195, 224, 51, 165, 67, 252, 137, 143, 155, 8, 110, 101, 45, 192, 84,
					54, 95, 101, 223, 210, 101, 208, 206, 178, 69, 78, 216, 156, 120, 115, 222, 226, 175, 219, 129, 242,
					96, 50, 45, 113, 13, 13, 128, 28, 23, 58, 208, 2, 83, 160, 162, 31, 128, 99, 9, 255, 215, 253, 192,
					79, 254, 192, 69, 8, 43, 65, 120, 142, 16, 104, 40, 204, 213, 15, 238, 42, 251, 78, 150, 254, 23,
					81, 72, 122, 86, 42, 246, 143, 6, 14, 118, 168, 38, 130, 77, 1, 97, 15, 198, 252, 251, 188, 159,
					129, 247, 43, 207, 135, 206, 221, 23, 222, 7, 241, 182, 142, 150, 127, 86, 95, 211, 99, 182, 247,
					182, 162, 66, 131, 75, 166, 237, 126, 42, 170, 212, 73, 253, 10, 142, 65, 157, 64, 185, 153, 218,
					150, 194, 32, 77, 71, 72, 146, 41, 65, 169, 185, 17, 133, 28, 49, 223, 93, 138, 149, 69, 237, 132,
					187, 16, 32, 215, 9, 164, 146, 12, 198, 100, 252, 209, 212, 168, 196},
			},
			isValid:       true,
			expectedError: "",
		},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		_ = keypairtestutils.SetupRsaKeyPair(test.keyID)
		err := verificationsymmetric.SignPKCS1v15(test.message, test.keyID)
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

func TestSignatureVerificationRSA(t *testing.T) {
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
		_ = keypairtestutils.SetupRsaKeyPair(test.keyID)
		// Don't check error as we want to test robustness of ValidateHMAC.
		_ = verificationsymmetric.SignPKCS1v15(test.message, test.keyID)
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		isValid, err := verificationsymmetric.ValidatePKCS1v15(test.message, test.keyID)
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

func TestSignatureVerificationModificationRSA(t *testing.T) {
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
					244, 59, 173, 128, 91, 8, 231, 81, 185, 60, 73, 224, 151, 173, 190, 76, 206, 235, 131, 221, 185, 79,
					199, 29, 137, 45, 215, 4, 61, 120, 38, 148, 172, 218, 211, 16, 242, 63, 84, 112, 122, 38, 145, 26,
					158, 126, 157, 125, 172, 228, 41, 71, 184, 171, 136, 128, 108, 167, 2, 38, 32, 123, 232, 103, 27,
					51, 149, 5, 69, 126, 197, 246, 111, 232, 130, 109, 237, 137, 135, 7, 188, 14, 175, 112, 243, 245,
					20, 170, 222, 185, 79, 218, 67, 21, 85, 4, 219, 113, 107, 237, 28, 96, 39, 228, 136, 255, 145, 37,
					231, 187, 199, 54, 240, 20, 176, 165, 253, 171, 59, 234, 163, 122, 2, 102, 175, 176, 158, 171, 211,
					190, 91, 210, 43, 209, 34, 63, 154, 131, 156, 130, 84, 239, 15, 173, 227, 20, 32, 75, 86, 24, 142,
					183, 169, 59, 93, 85, 106, 38, 4, 72, 62, 85, 7, 74, 224, 211, 228, 44, 0, 82, 239, 144, 40, 27,
					151, 133, 188, 133, 242, 64, 141, 135, 166, 215, 77, 53, 9, 151, 7, 141, 142, 53, 243, 65, 12, 113,
					153, 248, 143, 186, 254, 145, 222, 198, 233, 79, 231, 182, 175, 4, 183, 246, 144, 18, 104, 250, 19,
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
					46, 247, 224, 234, 187, 253, 168, 127, 252, 249, 96, 218, 173, 123, 79, 140, 142, 35, 216, 205, 14,
					24, 242, 175, 126, 95, 160, 191, 151, 49, 240, 200, 131, 187, 29, 201, 25, 85, 247, 106, 247, 42,
					99, 218, 163, 84, 66, 179, 181, 241, 27, 204, 191, 166, 97, 53, 115, 115, 67, 4, 197, 144, 44, 101,
					116, 15, 52, 156, 218, 55, 21, 184, 122, 142, 186, 130, 73, 214, 110, 103, 71, 221, 33, 157, 230,
					148, 79, 109, 100, 162, 219, 89, 213, 139, 148, 222, 82, 114, 104, 117, 136, 46, 195, 76, 26, 219,
					211, 95, 133, 109, 43, 217, 32, 215, 100, 92, 194, 211, 92, 97, 243, 82, 83, 191, 103, 60, 63, 120,
					242, 102, 114, 165, 143, 190, 195, 146, 62, 207, 88, 21, 215, 45, 231, 234, 216, 9, 112, 150, 83,
					224, 212, 120, 102, 164, 242, 202, 100, 100, 183, 236, 107, 114, 98, 224, 120, 89, 39, 82, 34, 115,
					239, 72, 201, 237, 155, 16, 104, 51, 2, 27, 215, 103, 239, 157, 186, 215, 35, 42, 219, 30, 98, 185,
					92, 126, 149, 118, 123, 60, 45, 98, 189, 183, 222, 250, 134, 130, 232, 83, 211, 210, 0, 231, 163,
					200, 190, 81, 172, 130, 158, 234, 103, 132, 146, 220, 252, 89, 236, 205, 106, 185, 145, 192, 93,
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
				Signature: []byte{18, 57, 110, 228, 70, 135, 88, 122, 227, 211, 176, 167, 128, 76, 243, 83, 3, 19,
					48, 247, 104, 73, 201, 76, 88, 81, 1, 195, 135, 250, 190, 67, 191, 126, 112, 82, 108, 80, 177, 206,
					91, 113, 97, 43, 94, 244, 7, 55, 86, 124, 213, 69, 42, 242, 196, 100, 114, 73, 109, 232, 171, 228,
					86, 173, 16, 126, 13, 50, 57, 90, 142, 21, 13, 123, 70, 54, 140, 178, 249, 24, 202, 244, 99, 227,
					215, 158, 110, 20, 18, 229, 134, 176, 137, 65, 47, 213, 4, 157, 124, 145, 138, 66, 254, 76, 156,
					103, 113, 38, 106, 111, 71, 180, 221, 155, 22, 174, 179, 151, 74, 113, 233, 163, 174, 222, 55, 12,
					148, 227, 73, 255, 5, 63, 219, 114, 37, 28, 171, 239, 127, 211, 92, 43, 7, 7, 132, 164, 196, 33,
					185, 129, 169, 97, 109, 5, 93, 35, 67, 111, 89, 141, 60, 100, 63, 22, 157, 6, 199, 176, 77, 53, 45,
					189, 33, 10, 31, 234, 177, 133, 105, 103, 63, 76, 20, 221, 230, 74, 139, 186, 195, 49, 194, 221,
					117, 118, 189, 202, 15, 48, 86, 103, 19, 181, 60, 204, 70, 48, 81, 181, 71, 19, 234, 148, 125, 25,
					238, 167, 30, 36, 61, 166, 131, 7, 199, 84, 212, 218, 53, 62, 21, 244, 35, 65, 48, 31, 95, 99, 73,
					43, 206, 72, 222, 195, 59, 246, 86, 193, 195, 253, 179, 122, 95, 222, 165, 225, 176, 68},
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
					46, 247, 224, 234, 187, 253, 168, 127, 252, 249, 96, 218, 173, 123, 79, 140, 142, 35, 216, 205, 14,
					24, 242, 175, 126, 95, 160, 191, 151, 49, 240, 200, 131, 187, 29, 201, 25, 85, 247, 106, 247, 42,
					99, 218, 163, 84, 66, 179, 181, 241, 27, 204, 191, 166, 97, 53, 115, 115, 67, 4, 197, 144, 44, 101,
					116, 15, 52, 156, 218, 55, 21, 184, 122, 142, 186, 130, 73, 214, 110, 103, 71, 221, 33, 157, 230,
					148, 79, 109, 100, 162, 219, 89, 213, 139, 148, 222, 82, 114, 104, 117, 136, 46, 195, 76, 26, 219,
					211, 95, 133, 109, 43, 217, 32, 215, 100, 92, 194, 211, 92, 97, 243, 82, 83, 191, 103, 60, 63, 120,
					242, 102, 114, 165, 143, 190, 195, 146, 62, 207, 88, 21, 215, 45, 231, 234, 216, 9, 112, 150, 83,
					224, 212, 120, 102, 164, 242, 202, 100, 100, 183, 236, 107, 114, 98, 224, 120, 89, 39, 82, 34, 115,
					239, 72, 201, 237, 155, 16, 104, 51, 2, 27, 215, 103, 239, 157, 186, 215, 35, 42, 219, 30, 98, 185,
					92, 126, 149, 118, 123, 60, 45, 98, 189, 183, 222, 250, 134, 130, 232, 83, 211, 210, 0, 231, 163,
					200, 190, 81, 172, 130, 158, 234, 103, 132, 146, 220, 252, 89, 236, 205, 106, 185, 145, 192, 93,
					222, 101, 180, 241},
			},
			expectedValue: false,
			expectedError: "failed to find any message integrity signature field in proto",
		},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		// Don't check error as we want to test robustness of ValidateHMAC.
		_ = verificationsymmetric.SignPKCS1v15(test.message, test.keyID)
		if test.receivedMessage != nil {
			log.Printf("Signature of Received Message: %v", test.receivedMessage.GetSignature())
		}
		isValid, err := verificationsymmetric.ValidatePKCS1v15(test.receivedMessage, test.keyID)
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

func TestSigning(t *testing.T) {
	tests := []struct {
		key                   []byte
		message               verificationsymmetric.VerifiableMessage
		expectedSignedMessage verificationsymmetric.VerifiableMessage
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
		err := verificationsymmetric.SignProto(test.message, test.key)
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
		message       verificationsymmetric.VerifiableMessage
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
		_ = verificationsymmetric.SignProto(test.message, test.key)
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		isValid, err := verificationsymmetric.ValidateHMAC(test.message, test.key)
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
		message         verificationsymmetric.VerifiableMessage
		receivedMessage verificationsymmetric.VerifiableMessage
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
		_ = verificationsymmetric.SignProto(test.message, test.key)
		if test.receivedMessage != nil {
			log.Printf("Signature of Received Message: %v", test.receivedMessage.GetSignature())
		}
		isValid, err := verificationsymmetric.ValidateHMAC(test.receivedMessage, test.key)
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
