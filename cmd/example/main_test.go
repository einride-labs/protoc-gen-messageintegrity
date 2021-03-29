package main

import (
	integpb "github.com/einride/protoc-gen-messageintegrity/internal/examples/proto/gen"
	"log"
	"os"
	"testing"
)

// ResultError is needed to avoid compiler optimization.
var resultError error

func BenchmarkSign(b *testing.B) {
	var sigSteeringCommand integpb.SteeringCommandVerification
	key := "a key for signing"
	os.Setenv(integpb.ImplicitMessageIntegrityKey, key)
	var err error
	for i := 0; i < b.N; i++ {
		sigSteeringCommand = integpb.SteeringCommandVerification{SteeringAngle: 5.0}
		if err := sigSteeringCommand.Sign(); err != nil {
			log.Fatalf("failed to sign proto: %v", err)
		}
	}
	resultError = err
}


// Result is needed to avoid compiler optimization.
var result bool
func BenchmarkVerify(b *testing.B) {
	var sigSteeringCommand integpb.SteeringCommandVerification
	key := "a key for signing"
	os.Setenv(integpb.ImplicitMessageIntegrityKey, key)
	if err := sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	var isValid bool
	var err error
	for i := 0; i < b.N; i++ {
		sigSteeringCommand = integpb.SteeringCommandVerification{SteeringAngle: 5.0}
		isValid, err = sigSteeringCommand.Verify()
		if err != nil {
			log.Fatalf("failed to verify proto: %v", err)
		}
	}
	result = isValid
}
