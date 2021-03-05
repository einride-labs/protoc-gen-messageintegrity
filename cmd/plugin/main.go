package main

import (
	"github.com/einride/protoc-gen-messageintegrity/internal/plugin"
	"log"
)

func main() {
	messageIntegrityPlugin := plugin.MessageIntegrityPlugin{}
	if err := messageIntegrityPlugin.Generate(); err != nil {
		log.Fatal(err)
	}
}
