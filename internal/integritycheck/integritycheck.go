// Package integrity check defines an Analyzer that check that ProtoMessages Signatures are used
package integritycheck

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"golang.org/x/tools/go/analysis"
	"google.golang.org/protobuf/proto"
)

var Analyzer = &analysis.Analyzer{
	Name: "integritylint",
	Doc:  "checks signatures are used if message integrity is enabled for protomessages",
	Run:  run,

}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
			de, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}

			fmt.Printf("type: %v, name: %v \n", de.Type ,de.Names)

			msg, ok := de.Type.(*proto.Message)
			prev := make(map[Type]int)
			types.lookupType(prev, de.Type)
			types.Look
			if !ok {
				return true
			}
			return true
		})
	}
	return nil, errors.New("not implemented yet")
}
