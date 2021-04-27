// Package integrity check defines an Analyzer that check that ProtoMessages Signatures are used
package integritycheck

import (
	"errors"
	"fmt"
	integritypb "github.com/einride/protoc-gen-messageintegrity/proto/gen/integrity/v1"
	"go/ast"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/loader"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
	"google.golang.org/protobuf/types/descriptorpb"
	"log"
	"strconv"
	"strings"
)

var Analyzer = &analysis.Analyzer{
	Name: "integritylint",
	Doc:  "checks signatures are used if message integrity is enabled for protomessages",
	Run:  run,
}

// run steps involved.
// 1. Go through the imports and see if any of them are proto imports by checking recursively if they import the
// internal proto implementation packages.
// 2. Go through each struct proto found from the previous and see if any of them have the message integrity signature
// option set for a field.
// 		a. Check the extensions on the fields and see if any of them are message_integrity_signature
// 		b. See that it is REQUIRED
// 3. Make a short list of these struct types.
// 4. Go through the file looking for proto.Marshal() calls on any of these types.
// 5. I found look that proto.Sign() is called immediately before it.
// 4. Go through the file looking for proto.Unmarshal() calls on any of these types.
// 5. I found look that proto.Verify() is called immediately after it.

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		// Map of proto message types that have implicit message integrity enabled so they can be looked up when
		// Marshal and unmarshal calls are found.
		p := protoIntegrityChecker{typeInfo: pass.TypesInfo, protoTypes: make(map[types.Type]struct{})}
		ast.Inspect(file, func(n ast.Node) bool {
			im, ok := n.(*ast.ImportSpec)
			if !ok {
				return true
			}
			path, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				log.Fatal(err)
			}
			if strings.Compare(path, "command-line-arguments") == 0 {
				// I don't know why this always appears as an import but I'm ignoring it.
				return true
			}
			var conf loader.Config
			conf.Import(path)
			prog, err := conf.Load()
			if err != nil {
				log.Fatal(err)
			}
			for pn := range prog.AllPackages {
				// Weak way of figuring out if an import is a proto message generated from protoc-go
				// I only look for proto message structs that have the options in dependencies which have protoimpl as
				// a dependency to save time.
				if pn.Path() != "google.golang.org/protobuf/runtime/protoimpl" {
					continue
				}
				integrityProtosMap, err := p.findIntegrityProtos(prog.InitialPackages())
				if err != nil {
					log.Fatal(err)
				}
				for t := range integrityProtosMap {
					tname := types.NewTypeName(token.NoPos, prog.Package(path).Pkg, t, nil)
					// Make it a as the proto.(Un)marshal calls take pointers so its easier for the map lookup.
					nt := types.NewPointer(types.NewNamed(tname, nil, nil))
					p.protoTypes[nt] = *new(struct{})
					to := p.typeInfo.ObjectOf(im.Name)
					pass.ExportObjectFact(to, &integrityFact{t: *nt})
				}
			}
			return true
		})
		// Now I have a list of all of the types find (Un)marshals of.
		ast.Inspect(file, p.parseProtoMarshals)
	}
	return nil, nil
}

type protoIntegrityChecker struct {
	typeInfo *types.Info
	protoTypes map[types.Type]struct{}
}

func (p *protoIntegrityChecker) findIntegrityProtos(packages []*loader.PackageInfo) (map[string]struct{}, error) {
	integrityProtoTypes := make(map[string]struct{})
	for _, p := range packages {
		for _, f := range p.Files {
			fmt.Println(f.Scope)
			for _, d := range f.Scope.Objects {
				if d.Kind != ast.Var {
					continue
				}
				// This really should be "file_example_" + <import_file_name> + "_.*_proto_rawDesc"
				// but I don't know how to get the file name of the proto file name
				if !strings.Contains(d.Name, "_proto_rawDesc") {
					continue
				}
				if d.Decl == nil {
					continue
				}
				as, ok := d.Decl.(*ast.ValueSpec)
				if !ok {
					fmt.Println("not assignment statement")
					continue
				}
				for _, v := range as.Values {
					fieldDescRaw, err := parseByteSlice(v)
					if err != nil {
						continue
					}
					fd := protoimpl.DescBuilder{RawDescriptor: fieldDescRaw}.Build().File
					if fd == nil {
						log.Fatal("failed to parse raw field desc")
					}
					protosMap := findSigRequiredProtos(fd)
					for k := range protosMap {
						// Map from a string of the type name from the proto file descriptor to the
						// types.Type representation for analysis.
						to, exists := f.Scope.Objects[k]
						if !exists {
							return nil, fmt.Errorf("proto Message type %v not found in scope", k)
						}
						ts, ok := to.Decl.(*ast.TypeSpec)
						if !ok {
							return nil, errors.New("decl could not be converted to a typeSpec")
						}
						t := p.TypeOf(ts.Type)
						if !ok {
							return nil, fmt.Errorf("proto Message object %v could not be converted to a type", k)
						}
						fmt.Println(t)
						integrityProtoTypes[k] = *new(struct{})
					}
				}
			}
		}
	}
	return integrityProtoTypes, nil
}

// Find (Un)Marshals of integrity enabled protos.
func  (p *protoIntegrityChecker) parseProtoMarshals(n ast.Node) bool {
	e, ok := n.(ast.Expr)
	if !ok {
		return true
	}
	callExpr, ok := e.(*ast.CallExpr)
	if !ok {
		return true
	}
	sel, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return true
	}

	// TODO(paulmolloy): Change to check the underlying src of the ident encase the import name was overridden to something else.
	if strings.Compare(getIdent(sel.X).Name, "proto") != 0 {
		return true
	}
	args := callExpr.Args
	var protoExpr ast.Expr
	switch sel.Sel.Name {
	case "Marshal":
		// Want 1st of 1 params.
		if len(args) != 1 {
			return true
		}
		protoExpr = args[0]
		// TODO(paulmolloy): Check if Sign is called at the end of the expression in the case its not an ident.
		fmt.Println("Checking against:")
		for pt := range p.protoTypes {
			fmt.Println(pt)
		}
	case "Unmarshal":
		// Want 2nd of 2 params.
		if len(args) != 2 {
			return true
		}
		protoExpr = args[1]
	default:
		// It's some other func from proto and we don't care.
		return true
	}
	fmt.Println(protoExpr)
	return true
}

// find the protos that have the message integrity signature option set for a field.
func findSigRequiredProtos(fd protoreflect.FileDescriptor) map[string]struct{} {
	protoMap := make(map[string]struct{})
	for i := 0; i < fd.Messages().Len(); i++ {
		m := fd.Messages().Get(i)
		fields := m.Fields()
		hasOption := false
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			opts := fd.Options().(*descriptorpb.FieldOptions)
			sigOption, ok := proto.GetExtension(opts, integritypb.E_MessageIntegritySignature).(*integritypb.MessageIntegritySignature)
			if !ok || fd.Kind() != protoreflect.BytesKind {
				continue // The signature can only be a bytes field, ignore everything else.
			} else if sigOption.GetBehaviour() != integritypb.SignatureBehaviour_SIGNATURE_BEHAVIOUR_REQUIRED &&
				sigOption.GetBehaviour() != integritypb.SignatureBehaviour_SIGNATURE_BEHAVIOUR_OPTIONAL {
				// Don't verify if the option isn't there or it's behaviour isn't required or optional.
				continue
			}
			hasOption = true
		}
		if hasOption {
			s := string(m.Name())
			protoMap[s] = *new(struct{})
		}
	}
	return protoMap
}

// integrityFact is a fact associated with types that are Protocol buffer Messages with the message integrity
// option enabled.
type integrityFact struct {
	t types.Pointer
}

func (i *integrityFact) String() string {
	// analysistest does not like "*"
	return fmt.Sprintf("found proto message type: %v with message integrity enabled", i.t.String()[1:])
}
func (*integrityFact) AFact() {}
