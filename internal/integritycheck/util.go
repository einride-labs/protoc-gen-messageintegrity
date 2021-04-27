package integritycheck

import (
	"errors"
	"go/ast"
	"strconv"
)

// reads a constant byte array in a ast.Composite lit and turns it into a runtime byte array.
func parseByteSlice(v ast.Expr) ([]byte, error) {
	// Sneakily I can parse this byte array into the field descriptor proto at run time.
	cl, ok := v.(*ast.CompositeLit)
	if !ok {
		return nil, errors.New("not a comp lit")
	}
	if cl.Elts == nil {
		return nil, errors.New("no elements")
	}
	var fieldDescRaw []byte
	for _, e := range cl.Elts {
		v, ok := e.(*ast.BasicLit)
		if !ok {
			continue
		}
		// I feel like this should work with bitset=8 but I get failed to parse 0x92 so 16
		// bits it is.
		ib, err := strconv.ParseInt(v.Value, 0, 16)
		if err != nil {
			return nil, err
		}
		b := byte(ib)
		fieldDescRaw = append(fieldDescRaw, b)
	}
	return fieldDescRaw, nil
}

// Gets the underlying ident of an expression
func getIdent(s ast.Expr) *ast.Ident {
	switch v := s.(type) {
	case *ast.CallExpr:
		return getIdent(v.Fun)
	case *ast.SelectorExpr:
		return getIdent(v.X)
	case *ast.Ident:
		return v
	default:
		return nil
	}
}
