package main

import (
	"github.com/einride/protoc-gen-messageintegrity/internal/messageintegrity"
	"log"
)

func main() {
	var plugin messageintegrity.Plugin
	if err := plugin.Generate(); err != nil {
		log.Fatal(err)
	}
}
