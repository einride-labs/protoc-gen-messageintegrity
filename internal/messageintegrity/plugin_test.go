package messageintegrity

import (
	verificationRSAOption "github.com/einride/protoc-gen-messageintegrity/internal/verificationRsaOption"
	v1 "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"google.golang.org/protobuf/proto"
	"log"
	"os"
	"testing"
)

const (
	// Key used for for symmetric message integrity verification.
	ImplicitMessageIntegrityKey = "IMPLICIT_MESSAGE_INTEGRITY_KEY"
	// KeyID Used to identify the RSA keypair being used.
	ImplicitMessageIntegrityKeyID = "IMPLICIT_MESSAGE_INTEGRITY_KEY_ID"
)

func TestSign(t *testing.T) {
	tests := []struct {
		key                   string
		keyID                 verificationRSAOption.KeyID
		message               *v1.SteeringCommandVerificationOption
		receivedSignedMessage *v1.SteeringCommandVerificationOption
		isValid               bool
		expectedError         string
	}{
		{
			key:     "some bytes",
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0},
			receivedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 6.0,
				// SHA 256 Sig Signature: []byte{31, 137, 186, 164, 173, 211, 74, 222, 39, 149, 108, 62, 70, 131, 158,
				// 11, 71, 31, 57, 246, 234, 41, 221, 245, 167, 205, 238, 97, 49, 245, 160, 120},
				Signature: []byte{18, 57, 110, 228, 70, 135, 88, 122, 227, 211, 176, 167, 128, 76, 243, 83, 3, 19, 48,
					247, 104, 73, 201, 76, 88, 81, 1, 195, 135, 250, 190, 67, 191, 126, 112, 82, 108, 80, 177, 206, 91,
					113, 97, 43, 94, 244, 7, 55, 86, 124, 213, 69, 42, 242, 196, 100, 114, 73, 109, 232, 171, 228, 86,
					173, 16, 126, 13, 50, 57, 90, 142, 21, 13, 123, 70, 54, 140, 178, 249, 24, 202, 244, 99, 227, 215,
					158, 110, 20, 18, 229, 134, 176, 137, 65, 47, 213, 4, 157, 124, 145, 138, 66, 254, 76, 156, 103,
					113, 38, 106, 111, 71, 180, 221, 155, 22, 174, 179, 151, 74, 113, 233, 163, 174, 222, 55, 12, 148,
					227, 73, 255, 5, 63, 219, 114, 37, 28, 171, 239, 127, 211, 92, 43, 7, 7, 132, 164, 196, 33, 185,
					129, 169, 97, 109, 5, 93, 35, 67, 111, 89, 141, 60, 100, 63, 22, 157, 6, 199, 176, 77, 53, 45, 189,
					33, 10, 31, 234, 177, 133, 105, 103, 63, 76, 20, 221, 230, 74, 139, 186, 195, 49, 194, 221, 117,
					118, 189, 202, 15, 48, 86, 103, 19, 181, 60, 204, 70, 48, 81, 181, 71, 19, 234, 148, 125, 25, 238,
					167, 30, 36, 61, 166, 131, 7, 199, 84, 212, 218, 53, 62, 21, 244, 35, 65, 48, 31, 95, 99, 73, 43,
					206, 72, 222, 195, 59, 246, 86, 193, 195, 253, 179, 122, 95, 222, 165, 225, 176, 68},
			},
			isValid:       true,
			expectedError: "",
		},
		{
			key:     "some bytes",
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0},
			receivedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 6.0,
				Signature: []byte{32, 137, 186, 164, 173, 211, 74, 222, 39, 149, 108, 62, 70, 131, 158, 11, 71, 31, 57,
					246, 234, 41, 221, 245, 167, 205, 238, 97, 49, 245, 160, 120},
			},
			isValid:       false,
			expectedError: "",
		},
	}
	for _, test := range tests {
		os.Setenv(ImplicitMessageIntegrityKey, test.key)
		os.Setenv(ImplicitMessageIntegrityKeyID, string(test.keyID))
		_ = verificationRSAOption.SetupKeyPair(test.keyID)
		err := test.message.Sign()
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		if err != nil && err.Error() != test.expectedError {
			t.Errorf("Error actual = %v, and expected = %v", err, test.expectedError)
		}
		if err == nil && test.expectedError != "" {
			t.Errorf("Error actual = nil, and expected = %v", test.expectedError)
		}
		isValid, err := test.receivedSignedMessage.Verify()
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		if err != nil && err.Error() != test.expectedError {
			t.Errorf("Error actual = %v, and expected = %v", err, test.expectedError)
		}
		if err == nil && test.expectedError != "" {
			t.Errorf("Error actual = nil, and expected = %v", test.expectedError)
		}
		if isValid != test.isValid {
			t.Errorf("error actual signed message: %v expected signed message: %v", isValid, test.isValid)
		}
	}

}

func TestSignVerify(t *testing.T) {
	tests := []struct {
		key                   string
		keyID                 verificationRSAOption.KeyID
		message               *v1.SteeringCommandVerificationOption
		expectedSignedMessage *v1.SteeringCommandVerificationOption
		isValid               bool
		expectedError         string
	}{
		{
			key:     "some bytes",
			keyID:   "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0},
			expectedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 6.0,
				// SHA 256 Sig Signature: []byte{31, 137, 186, 164, 173, 211, 74, 222, 39, 149, 108, 62, 70, 131, 158,
				// 11, 71, 31, 57, 246, 234, 41, 221, 245, 167, 205, 238, 97, 49, 245, 160, 120},
				Signature: []byte{18, 57, 110, 228, 70, 135, 88, 122, 227, 211, 176, 167, 128, 76, 243, 83, 3, 19, 48,
					247, 104, 73, 201, 76, 88, 81, 1, 195, 135, 250, 190, 67, 191, 126, 112, 82, 108, 80, 177, 206, 91,
					113, 97, 43, 94, 244, 7, 55, 86, 124, 213, 69, 42, 242, 196, 100, 114, 73, 109, 232, 171, 228, 86,
					173, 16, 126, 13, 50, 57, 90, 142, 21, 13, 123, 70, 54, 140, 178, 249, 24, 202, 244, 99, 227, 215,
					158, 110, 20, 18, 229, 134, 176, 137, 65, 47, 213, 4, 157, 124, 145, 138, 66, 254, 76, 156, 103,
					113, 38, 106, 111, 71, 180, 221, 155, 22, 174, 179, 151, 74, 113, 233, 163, 174, 222, 55, 12, 148,
					227, 73, 255, 5, 63, 219, 114, 37, 28, 171, 239, 127, 211, 92, 43, 7, 7, 132, 164, 196, 33, 185,
					129, 169, 97, 109, 5, 93, 35, 67, 111, 89, 141, 60, 100, 63, 22, 157, 6, 199, 176, 77, 53, 45, 189,
					33, 10, 31, 234, 177, 133, 105, 103, 63, 76, 20, 221, 230, 74, 139, 186, 195, 49, 194, 221, 117,
					118, 189, 202, 15, 48, 86, 103, 19, 181, 60, 204, 70, 48, 81, 181, 71, 19, 234, 148, 125, 25, 238,
					167, 30, 36, 61, 166, 131, 7, 199, 84, 212, 218, 53, 62, 21, 244, 35, 65, 48, 31, 95, 99, 73, 43,
					206, 72, 222, 195, 59, 246, 86, 193, 195, 253, 179, 122, 95, 222, 165, 225, 176, 68},
			},
			isValid:       true,
			expectedError: "",
		},
		{
			key:   "some bytes",
			keyID: "test_verification_id_1",
			message: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 6.0,
			},
			expectedSignedMessage: &v1.SteeringCommandVerificationOption{
				SteeringAngle: 6.0,
				Signature: []byte{32, 137, 186, 164, 173, 211, 74, 222, 39, 149, 108, 62, 70, 131, 158, 11, 71, 31, 57,
					246, 234, 41, 221, 245, 167, 205, 238, 97, 49, 245, 160, 120},
			},
			isValid:       false,
			expectedError: "",
		},
	}
	for _, test := range tests {
		os.Setenv(ImplicitMessageIntegrityKey, test.key)
		os.Setenv(ImplicitMessageIntegrityKeyID, string(test.keyID))
		_ = verificationRSAOption.SetupKeyPair(test.keyID)
		err := test.message.Sign()
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
			t.Errorf("error actual signed message: %v expected signed message: %v", test.message, test.expectedSignedMessage)
		}
	}

}
