// Package integrity check defines an Analyzer that check that ProtoMessages Signatures are used
package integritycheck

import (
	"errors"
	"golang.org/x/tools/go/analysis"
)

var Analyzer = &analysis.Analyzer{
	Name: "integritylint",
	Doc:  "checks signatures are used if message integrity is enabled for protomessages",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	return nil, errors.New("not implemented yet")
}
