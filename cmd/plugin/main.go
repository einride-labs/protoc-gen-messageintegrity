package main

import (
	"github.com/einride/protoc-gen-messageintegrity/internal/messageintegrity"
	"log"
)

func main() {
	plugin := messageintegrity.Plugin{Version: messageintegrity.VerificationSymmetric}
	if err := plugin.Generate(); err != nil {
		log.Fatal(err)
	}
}
