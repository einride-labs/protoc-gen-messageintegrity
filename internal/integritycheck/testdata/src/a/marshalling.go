package main

import (
	integpb "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1" // want integpb:`found proto message type: github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1.SteeringCommandVerificationOption with message integrity enabled`
	"google.golang.org/protobuf/proto"
	"log"
	"os"
)

func main() {
	key := "a key for signing"
	os.Setenv(integpb.ImplicitMessageIntegrityKey, key)
	signedExample()
	notSignedExample()
	VerificationExample()
	noVerificationExample()
	notSignedUntilAfterMarshalExample()
	noIntegrityOptionExample()
	// TODO(paulmolloy): These cases are not currently handled by the linter.
	// signedButLaterModifiedExample()
	// accessBeforeVerificationExample()
}

func signedExample() {
	sigSteeringCommand := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0} // want sigSteeringCommand: `found marshal of message integrity enabled proto message`

	// Sending
	if err := sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	_, err := proto.Marshal(&sigSteeringCommand)
	if err != nil {
		log.Fatalf("failed to marshal verified message: %v ", err)
	}
}

func notSignedExample() {
	sigSteeringCommandUnsigned := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0} // want sigSteeringCommandUnsigned: `found marshal of message integrity enabled proto message`
	_, err := proto.Marshal(&sigSteeringCommandUnsigned)                                        // want `found possible marshalling of integrity proto before signing`
	if err != nil {
		log.Fatalf("failed to marshal verified message: %v ", err)
	}
}

func notSignedUntilAfterMarshalExample() {
	sigSteeringCommandSignedLate := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0} // want sigSteeringCommandSignedLate: `found marshal of message integrity enabled proto message`
	_, err := proto.Marshal(&sigSteeringCommandSignedLate)                                        // want `found possible marshalling of integrity proto before signing`
	if err != nil {
		log.Fatalf("failed to marshal verified message: %v ", err)
	}
	sigSteeringCommandSignedLate.Sign()
}

/*
func signedButLaterModifiedExample() {
	sigSteeringCommand := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0} // want sigSteeringCommand: `found marshal of message integrity enabled proto message`

	// Sending
	if err := sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	sigSteeringCommand = integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0}
	_, err := proto.Marshal(&sigSteeringCommand) // want `found possible marshalling of integrity proto before signing`
	if err != nil {
		log.Fatalf("failed to marshal verified message: %v ", err)
	}
}
*/

func VerificationExample() {
	var isValid bool
	sigSteeringCommand := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0} // want sigSteeringCommand: `found marshal of message integrity enabled proto message`

	// Sending
	if err := sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	data, err := proto.Marshal(&sigSteeringCommand)
	if err != nil {
		log.Fatalf("failed to marshal verified message: %v ", err)
	}

	// Receiving
	var receivedMessage integpb.SteeringCommandVerificationOption // want receivedMessage: `found unmarshal of message integrity enabled proto message`
	if err = proto.Unmarshal(data, &receivedMessage); err != nil {
		log.Fatal(err)
	}

	isValid, err = receivedMessage.Verify()

	if !isValid || err != nil {
		log.Fatalf("failed to verify proto: %v", err)
	}
}

func noVerificationExample() {
	sigSteeringCommand := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0} // want sigSteeringCommand: `found marshal of message integrity enabled proto message`

	// Sending
	if err := sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	data, err := proto.Marshal(&sigSteeringCommand)
	if err != nil {
		log.Fatalf("failed to marshal verified message: %v ", err)
	}

	// Receiving
	var receivedMessage integpb.SteeringCommandVerificationOption  // want receivedMessage: `found unmarshal of message integrity enabled proto message`
	if err = proto.Unmarshal(data, &receivedMessage); err != nil { // want `found possible unmarshalling of integrity proto without verifying afterwards`
		log.Fatal(err)
	}
}

/*
func accessBeforeVerificationExample() {
	var isValid bool
	sigSteeringCommand := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0} // want sigSteeringCommand: `found marshal of message integrity enabled proto message`

	// Sending
	if err := sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	data, err := proto.Marshal(&sigSteeringCommand)
	if err != nil {
		log.Fatalf("failed to marshal verified message: %v ", err)
	}

	// Receiving
	var receivedMessage integpb.SteeringCommandVerificationOption  // want receivedMessage: `found unmarshal of message integrity enabled proto message`
	if err = proto.Unmarshal(data, &receivedMessage); err != nil { // want `found possible access or overwrite of unmarshalled of integrity proto without verifying before`
		log.Fatal(err)
	}
	receivedMessage = integpb.SteeringCommandVerificationOption{}
	isValid, err = receivedMessage.Verify()

	if !isValid || err != nil {
		log.Fatalf("failed to verify proto: %v", err)
	}
}
*/

func noIntegrityOptionExample() {
	var isValid bool
	sigSteeringCommandTwo := integpb.SteeringCommandVerification{SteeringAngle: 5.0}

	// Sending
	if err := sigSteeringCommandTwo.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	data, err := proto.Marshal(&sigSteeringCommandTwo)
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
