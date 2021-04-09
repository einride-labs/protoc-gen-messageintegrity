package main

import (
	"github.com/einride/protoc-gen-messageintegrity/internal/integritycheck"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(integritycheck.Analyzer)
}
