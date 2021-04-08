package messageintegrity

import (
	v1 "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"google.golang.org/protobuf/proto"
	"log"
	"os"
	"testing"
)

const ImplicitMessageIntegrityKey = "IMPLICIT_MESSAGE_INTEGRITY_KEY"

func TestSign(t *testing.T) {
	tests := []struct {
		key                   string
		message               *v1.SteeringCommandVerification
		receivedSignedMessage *v1.SteeringCommandVerification
		isValid               bool
		expectedError         string
	}{
		{key: "some bytes", message: &v1.SteeringCommandVerification{SteeringAngle: 6.0}, receivedSignedMessage: &v1.SteeringCommandVerification{SteeringAngle: 6.0, Signature: []byte{31, 137, 186, 164, 173, 211, 74, 222, 39, 149, 108, 62, 70, 131, 158, 11, 71, 31, 57, 246, 234, 41, 221, 245, 167, 205, 238, 97, 49, 245, 160, 120}}, isValid: true, expectedError: ""},
		{key: "some bytes", message: &v1.SteeringCommandVerification{SteeringAngle: 6.0}, receivedSignedMessage: &v1.SteeringCommandVerification{SteeringAngle: 6.0, Signature: []byte{32, 137, 186, 164, 173, 211, 74, 222, 39, 149, 108, 62, 70, 131, 158, 11, 71, 31, 57, 246, 234, 41, 221, 245, 167, 205, 238, 97, 49, 245, 160, 120}}, isValid: false, expectedError: ""},
	}
	for _, test := range tests {
		os.Setenv(ImplicitMessageIntegrityKey, test.key)
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
		message               *v1.SteeringCommandVerification
		expectedSignedMessage *v1.SteeringCommandVerification
		isValid               bool
		expectedError         string
	}{
		{key: "some bytes", message: &v1.SteeringCommandVerification{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerification{SteeringAngle: 6.0, Signature: []byte{31, 137, 186, 164, 173, 211, 74, 222, 39, 149, 108, 62, 70, 131, 158, 11, 71, 31, 57, 246, 234, 41, 221, 245, 167, 205, 238, 97, 49, 245, 160, 120}}, isValid: true, expectedError: ""},
		{key: "some bytes", message: &v1.SteeringCommandVerification{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerification{SteeringAngle: 6.0, Signature: []byte{32, 137, 186, 164, 173, 211, 74, 222, 39, 149, 108, 62, 70, 131, 158, 11, 71, 31, 57, 246, 234, 41, 221, 245, 167, 205, 238, 97, 49, 245, 160, 120}}, isValid: false, expectedError: ""},
	}
	for _, test := range tests {
		os.Setenv(ImplicitMessageIntegrityKey, test.key)
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
