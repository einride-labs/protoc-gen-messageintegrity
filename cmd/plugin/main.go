package main

import (
	"github.com/einride/protoc-gen-messageintegrity/internal/messageintegrity"
	"log"
)

func main() {
	messageIntegrityPlugin := messageintegrity.Plugin{}
	if err := messageIntegrityPlugin.Generate(); err != nil {
		log.Fatal(err)
	}
}
