package main

import (
	"fmt"
	"google.golang.org/protobuf/proto"
	"log"

	integpb "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
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
	sigSteeringCommand := integpb.SteeringCommandVerification{SteeringAngle: 5.0}
	if err = sigSteeringCommand.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	isValid, err := sigSteeringCommand.Verify()
	if err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	fmt.Printf("Proto message signature isValid: %v", isValid)
}
