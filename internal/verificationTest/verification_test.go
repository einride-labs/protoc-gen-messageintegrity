package verificationTest

import (
	"github.com/einride/protoc-gen-messageintegrity/internal/verification"
	v1 "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"google.golang.org/protobuf/proto"
	"gotest.tools/v3/assert"
	"log"
	"testing"
)

func TestSigning(t *testing.T) {
	tests := []struct {
		key                   []byte
		message               verification.VerifiableMessage
		expectedSignedMessage verification.VerifiableMessage
		isValid               bool
		expectedError         string
	}{
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, isValid: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, isValid: true, expectedError: ""},
		{key: nil, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedSignedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, isValid: false, expectedError: "key was nil"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: nil, expectedSignedMessage: nil, isValid: true, expectedError: "message was nil"},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		err := verification.SignProto(test.message, test.key)
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
		message       verification.VerifiableMessage
		expectedValue bool
		expectedError string
	}{
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0}, expectedValue: true, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, expectedValue: true, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{}, expectedValue: true, expectedError: ""},
		{key: nil, message: &v1.SteeringCommandVerificationOption{}, expectedValue: false, expectedError: "key was nil"},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: nil, expectedValue: false, expectedError: "message was nil"},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		// Don't check error as we want to test robustness of ValidateHMAC.
		_ = verification.SignProto(test.message, test.key)
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		isValid, err := verification.ValidateHMAC(test.message, test.key)
		if err != nil && err.Error() != test.expectedError {
			t.Errorf("Error actual = %v, and expected = %v", err, test.expectedError)
		}
		if err == nil && test.expectedError != "" {
			t.Errorf("Error actual = nil, and expected = %v", test.expectedError)
		}
		assert.Assert(t, isValid == test.expectedValue)
	}
}

func TestSignatureVerificationModification(t *testing.T) {
	tests := []struct {
		key             []byte
		message         verification.VerifiableMessage
		receivedMessage verification.VerifiableMessage
		expectedValue   bool
		expectedError   string
	}{
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 5.0}, receivedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, expectedValue: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, receivedMessage: &v1.SteeringCommandVerificationOption{}, expectedValue: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{}, receivedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{122, 226, 141, 14, 125, 93, 5, 148, 213, 252, 225, 147, 142, 195, 174, 247, 49, 164, 86, 20, 9, 189, 217, 122, 180, 228, 79, 20, 152, 191, 55, 12}}, expectedValue: false, expectedError: ""},
		{key: []byte{253, 131, 172, 77, 207, 188, 17, 98, 0, 235, 48, 62, 175, 191, 75, 36, 181, 119, 22, 36, 95, 180, 254, 180, 180, 14, 39, 255, 104, 211, 146, 113}, message: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0}, receivedMessage: &v1.SteeringCommandVerificationOption{SteeringAngle: 6.0, Signature: []byte{5, 151, 155, 117, 81, 80, 154, 220, 0, 88, 88, 194, 100, 6, 74, 66, 99, 251, 28, 141, 118, 114, 87, 140, 120, 207, 59, 210, 133, 179, 150, 107}}, expectedValue: true, expectedError: ""},
	}
	for _, test := range tests {
		log.Printf("Case: %v", test.message)
		// Don't check error as we want to test robustness of ValidateHMAC.
		_ = verification.SignProto(test.message, test.key)
		if test.message != nil {
			log.Printf("Signature: %v", test.message.GetSignature())
		}
		isValid, err := verification.ValidateHMAC(test.receivedMessage, test.key)
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
