package main

import (
	keypairtestutils "github.com/einride/protoc-gen-messageintegrity/internal/keypairtestutils"
	"github.com/einride/protoc-gen-messageintegrity/internal/verificationsymmetric"
	integpb "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"google.golang.org/protobuf/proto"
	"log"
	"os"
	"testing"
)

// ResultError is needed to avoid compiler optimization.
var resultError error

func BenchmarkSign(b *testing.B) {
	var sigSteeringCommand integpb.SteeringCommandVerificationOption
	key := "a key for signing"

	os.Setenv(integpb.ImplicitMessageIntegrityKey, key)
	keyID := verificationsymmetric.KeyID("test_verification_id_1")
	os.Setenv(integpb.ImplicitMessageIntegrityKeyID, string(keyID))
	_ = keypairtestutils.SetupRsaKeyPair(keyID)

	var err error
	for i := 0; i < b.N; i++ {
		sigSteeringCommand = integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0}
		if err := sigSteeringCommand.Sign(); err != nil {
			log.Fatalf("failed to sign proto: %v", err)
		}
	}
	resultError = err
}

// Result is needed to avoid compiler optimization.
var result bool

func BenchmarkVerify(b *testing.B) {
	key := "a key for signing"
	os.Setenv(integpb.ImplicitMessageIntegrityKey, key)
	keyID := verificationsymmetric.KeyID("test_verification_id_1")
	os.Setenv(integpb.ImplicitMessageIntegrityKeyID, string(keyID))
	_ = keypairtestutils.SetupRsaKeyPair(keyID)
	sigSteeringCommand := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0}
	if err := sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	var isValid bool
	var err error
	for i := 0; i < b.N; i++ {
		isValid, err = sigSteeringCommand.Verify()
		if err != nil {
			log.Fatalf("failed to verify proto: %v", err)
		}
	}
	result = isValid
}

func BenchmarkVerifyE2E(b *testing.B) {
	key := "a key for signing"
	os.Setenv(integpb.ImplicitMessageIntegrityKey, key)
	keyID := verificationsymmetric.KeyID("test_verification_id_1")
	os.Setenv(integpb.ImplicitMessageIntegrityKeyID, string(keyID))
	_ =  keypairtestutils.SetupRsaKeyPair(keyID)
	var isValid bool
	for i := 0; i < b.N; i++ {
		sigSteeringCommand := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0}

		// Sending
		if err := sigSteeringCommand.Sign(); err != nil {
			log.Fatalf("failed to sign proto: %v", err)
		}
		data, err := proto.Marshal(&sigSteeringCommand)
		if err != nil {
			log.Fatalf("failed to marshal verified message: %v ", err)
		}

		// Receiving
		var receivedMessage integpb.SteeringCommandVerificationOption
		if err = proto.Unmarshal(data, &receivedMessage); err != nil {
			log.Fatal(err)
		}

		isValid, err = receivedMessage.Verify()

		if !isValid || err != nil {
			log.Fatalf("failed to verify proto: %v", err)
		}
	}
	result = isValid
}

func BenchmarkBaselineE2E(b *testing.B) {
	var err error
	for i := 0; i < b.N; i++ {
		sigSteeringCommand := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0}

		// Sending
		data, err := proto.Marshal(&sigSteeringCommand)
		if err != nil {
			log.Fatalf("failed to marshal verified message: %v ", err)
		}

		// Receiving
		var receivedMessage integpb.SteeringCommandVerificationOption
		if err = proto.Unmarshal(data, &receivedMessage); err != nil {
			log.Fatal(err)
		}
		if err != nil {
			log.Fatalf("failed to verify proto: %v", err)
		}
	}
	resultError = err
}
