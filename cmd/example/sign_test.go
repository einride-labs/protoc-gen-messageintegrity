package main

import (
	"testing"
	"fmt"
	"gotest.tools/v3/assert"
	v1 "github.com/einride/thesis-implicit-message-integrity/internal/examples/proto/gen"
)


// TODO(paulmolloy): A demo of the system will probably be run here.
func TestMarshal(t *testing.T) {
	fmt.Println("Hello Implict Message Integrity")
	steeringCommand := &v1.SteeringCommand{SteeringAngle: 5.0}
	fmt.Println(fmt.Printf("The steering angle is: %f", steeringCommand.SteeringAngle));
	assert.Assert(t, true)
}