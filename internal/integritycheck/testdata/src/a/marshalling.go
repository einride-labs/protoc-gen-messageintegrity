package main

import (
	integpb "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1" // want integpb:`found proto message type: struct{state google.golang.org/protobuf/internal/impl.MessageState; si... with message integrity enabled`
	"google.golang.org/protobuf/proto"
	"log"
	"os"
)

func main() {
	integrityVerificationExample()
}

func integrityVerificationExample() {
	key := "a key for signing"
	os.Setenv(integpb.ImplicitMessageIntegrityKey, key)

	var isValid bool
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
	sigSteeringCommandTwo := integpb.SteeringCommandVerification{SteeringAngle: 5.0}

	// Sending
	if err := sigSteeringCommandTwo.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	data, err = proto.Marshal(&sigSteeringCommandTwo)
	if err != nil {
		log.Fatalf("failed to marshal verified message: %v ", err)
	}

	// Receiving
	var receivedMessageTwo integpb.SteeringCommandVerification
	if err = proto.Unmarshal(data, &receivedMessageTwo); err != nil {
		log.Fatal(err)
	}

	isValid, err = receivedMessageTwo.Verify()

	if !isValid || err != nil {
		log.Fatalf("failed to verify proto: %v", err)
	}
}
