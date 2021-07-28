package main

import (
	"fmt"
	"github.com/einride/protoc-gen-messageintegrity/internal/keypairtestutils"
	verificationoptionrsa "github.com/einride/protoc-gen-messageintegrity/internal/verificationsymmetric"
	integpb "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"google.golang.org/protobuf/proto"
	"log"
	"os"
)

// TODO(paulmolloy): A demo of the system will probably be run here.
func main() {
	// Hello world just a normal steering command with no integrity verification.
	fmt.Println("Hello Implicit Message Integrity")
	steeringCommand := &integpb.SteeringCommand{SteeringAngle: 5.0}

	message, err := proto.Marshal(steeringCommand)
	if err != nil {
		log.Fatalln("Failed to encode steering command:", err)
	}
	receivedMsg := &integpb.SteeringCommand{}
	if err = proto.Unmarshal(message, receivedMsg); err != nil {
		log.Fatalln("Failed to decode address book:", err)
	}
	fmt.Printf("The steering angle is: %f", receivedMsg.SteeringAngle)

	// Most basic hmac integrity verification by adding a field "signature" to the proto.
	// Fails to sign if the Option version of verification is used by the generation.
	sigSteeringCommand := integpb.SteeringCommandVerification{SteeringAngle: 6.0}
	if err = sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("Failed to sign proto: %v", err)
	}
	isValid, err := sigSteeringCommand.Verify()
	if err != nil {
		log.Fatalf("failed to sign proto: %v\n", err)
	}
	fmt.Printf("Proto message signature isValid: %v\n", isValid)

	// RSA Example


	keyID := verificationoptionrsa.KeyID("test_verification_id_1")

	fmt.Printf("Key id : %v\n", keyID)
	os.Setenv(integpb.ImplicitMessageIntegrityKeyID, string(keyID))
	if err := keypairtestutils.SetupRsaKeyPair(keyID); err != nil {
		log.Fatalf("failed to setup keypair for example: %v\n", err)
	}
	steeringCmd := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0}
	if err := steeringCmd.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	isValid, err = steeringCmd.Verify()
	if err != nil {
		log.Fatalf("faild to verify proto: %v\n", err)
	}
	fmt.Printf("Proto message signature isValid: %v\n", isValid)

}
