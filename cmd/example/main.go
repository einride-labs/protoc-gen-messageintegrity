package main

import (
	"encoding/csv"
	"fmt"
	"github.com/einride/protoc-gen-messageintegrity/internal/keypairtestutils"
	"github.com/einride/protoc-gen-messageintegrity/internal/verificationsymmetric"
	evalpb "github.com/einride/protoc-gen-messageintegrity/proto/gen/evaluation/v1"
	integpb "github.com/einride/protoc-gen-messageintegrity/proto/gen/example/v1"
	"google.golang.org/protobuf/proto"
	"log"
	"math/rand"
	"os"
	"strconv"
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
		log.Printf("Failed to sign proto: %v", err)
	}
	isValid, err := sigSteeringCommand.Verify()
	if err != nil {
		log.Printf("failed to sign proto: %v\n", err)
	}
	fmt.Printf("Proto message signature isValid: %v\n", isValid)

	// RSA Example


	keyID := verificationsymmetric.KeyID("test_verification_id_1")

	fmt.Printf("Key id : %v\n", keyID)
	os.Setenv(integpb.ImplicitMessageIntegrityKeyID, string(keyID))
	if err := keypairtestutils.SetupKeyPair(keyID); err != nil {
		log.Fatalf("failed to setup keypair for example: %v\n", err)
	}
	steeringCmd := integpb.SteeringCommandVerificationOption{SteeringAngle: 5.0}
	marshalled, err := proto.Marshal(&steeringCmd)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("steeringCommand size unsigned: %v\n", len(marshalled))
	if err := steeringCmd.Sign(); err != nil {
		log.Fatalf("failed to sign proto: %v", err)
	}
	isValid, err = steeringCmd.Verify()
	if err != nil {
		log.Fatalf("faild to verify proto: %v\n", err)
	}
	fmt.Printf("Proto message signature isValid: %v\n", isValid)
	marshalled, err = proto.Marshal(&steeringCmd)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("steeringCommand size signed: %v\n", len(marshalled))

	file, err := os.Create("eval_size_results_option_2048_rsa.csv")
	if err != nil {
		log.Fatalf("Failed to create csv: %v", err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	line := []string{"payload (bytes)", "unsigned size (bytes)", "signed size (bytes)"}
	err = writer.Write(line)
	if err != nil {
		log.Fatal(err)
	}

	sizeEval(0,1000, 2048, writer)



}


func sizeEval(minPayloadSize, maxPayloadSize, keySize int, fw *csv.Writer) {

	evalMsg := evalpb.EvaulationOption{}

	payload := make([]byte, maxPayloadSize)
	rand.Read(payload)

	for i:= minPayloadSize; i<maxPayloadSize; i += 10 {
		evalMsg = evalpb.EvaulationOption{Payload:  payload[:i]}

		marshalled, err := proto.Marshal(&evalMsg)
		if err != nil {
			log.Fatal(err)
		}

		size := len(marshalled)
		fmt.Println(size)
	if err := evalMsg.Sign(); err != nil {
			log.Fatal(err)
		}

		fmt.Println(evalMsg.Payload)
		marshalled, err = proto.Marshal(&evalMsg)
		if err != nil {
			log.Fatal(err)
		}

		sizeSigned := len(marshalled)
		fmt.Println(sizeSigned)
		line := []string{strconv.Itoa(i), strconv.Itoa(size), strconv.Itoa(sizeSigned)}
		if err = fw.Write(line); err != nil {
			log.Fatalf("Failed to save line: %v", err)
		}
	}
}

