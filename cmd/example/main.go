package main

import (
"fmt"
	"google.golang.org/protobuf/proto"
	"log"

	integpb "github.com/einride/thesis-implicit-message-integrity/internal/examples/proto/gen"
)


// TODO(paulmolloy): A demo of the system will probably be run here.
func main() {
	fmt.Println("Hello Implicit Message Integrity")
	steeringCommand := &integpb.SteeringCommand{SteeringAngle: 5.0}

	message, err := proto.Marshal(steeringCommand);
	if err != nil{
		log.Fatalln("Failed to encode address book:", err)
	}
	receivedMsg := &integpb.SteeringCommand{}
	if err = proto.Unmarshal(message, receivedMsg); err != nil {
		log.Fatalln("Failed to decode address book:", err)
	}
	//
	fmt.Println(fmt.Printf("The steering angle is: %f", receivedMsg.SteeringAngle));
}
