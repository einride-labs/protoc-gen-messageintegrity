package integritycheck

import (
	"errors"
	"go/ast"
	"strconv"
	"go/token"
	"log"
	"strings"
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

func getImportPath(n ast.Node) (*ast.ImportSpec, string, bool) {
	im, ok := n.(*ast.ImportSpec)
	if !ok {
		return nil, "", false
	}
	path, err := strconv.Unquote(im.Path.Value)
	if err != nil {
		log.Fatal(err)
	}
	if strings.Compare(path, "command-line-arguments") == 0 {
		// I don't know why this always appears as an import but I'm ignoring it.
		return im, "", false
	}
	return im, path, true
}

func castSelector(n ast.Node) (*ast.SelectorExpr, []ast.Expr, bool) {
	e, ok := n.(ast.Expr)
	if !ok {
		return nil, nil, false
	}
	callExpr, ok := e.(*ast.CallExpr)
	if !ok {
		return nil, nil, false
	}
	sel, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, nil, false
	}
	return sel, callExpr.Args, true
}

func castAddrOp(e ast.Expr) (*ast.Ident, bool) {
	addrExpr, ok := e.(*ast.UnaryExpr)
	if !ok {
		return nil, false
	}
	if addrExpr.Op != token.AND {
		return nil, false
	}
	ident, ok := addrExpr.X.(*ast.Ident)
	if !ok {
		return nil, false
	}
	return ident, true
}

func castProtoRawDesc(o *ast.Object) (ast.Expr, bool) {
	if o.Kind != ast.Var {
		return nil, false
	}
	// This really should be "file_example_" + <import_file_name> + "_.*_proto_rawDesc"
	// but I don't know how to get the file name of the proto file name
	if !strings.Contains(o.Name, "_proto_rawDesc") {
		return nil, false
	}
	if o.Decl == nil {
		return nil, false
	}
	as, ok := o.Decl.(*ast.ValueSpec)
	if !ok {
		// Not an assignment statement")
		return nil, false
	}
	if len(as.Values) != 1 {
		return nil, false
	}
	return as.Values[0], true
}
