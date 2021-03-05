package v1

import (
	verification "github.com/einride/protoc-gen-messageintegrity/internal/verification"
	os "os"
)

const ImplicitMessageIntegrityKey = "IMPLICIT_MESSAGE_INTEGRITY_KEY"

func (x *SteeringCommandVerification) Sign() error {
	key := os.Getenv(ImplicitMessageIntegrityKey)
	return verification.SignProto(x, []byte(key))
}

func (x *SteeringCommandVerification) Verify() (bool, error) {
	key := os.Getenv(ImplicitMessageIntegrityKey)
	return verification.ValidateHMAC(x, []byte(key))
}
