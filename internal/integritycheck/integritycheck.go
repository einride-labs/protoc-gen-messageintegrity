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
		p := protoIntegrityChecker{
			pass:        pass,
			protoTypes:  make(map[string]struct{}),
			marshals:    make(map[types.Object]token.Pos),
			unmarshalls: make(map[types.Object]token.Pos),
		}
		ast.Inspect(file, p.checkImportsForIntegrityProtos)
		// Now I have a list of all of the types find (Un)marshals of.
		ast.Inspect(file, p.parseProtoMarshals)
		// Now figure out the locations of the Sign()s and Verify()s and make sure they are where they need to be.
		ast.Inspect(file, p.checkSignsVerifies)
		p.reportUnsignedMarshals()
		p.reportUnverifiedUnmarshals()
	}
	return nil, nil
}

type protoIntegrityChecker struct {
	pass        *analysis.Pass
	protoTypes  map[string]struct{}
	marshals    map[types.Object]token.Pos
	unmarshalls map[types.Object]token.Pos
}

// isMarshalledBefore returns true if there was a call to marshal the ident before the sign.
func (p *protoIntegrityChecker) isMarshalledBefore(id *ast.Ident) bool {
	return !p.isBefore(id, p.marshals)
}

// isUnmarshalledAfter returns true if there was a call to Unmarshal the ident after the Verify.
func (p *protoIntegrityChecker) isUnmarshalledAfter(id *ast.Ident) bool {
	return p.isBefore(id, p.unmarshalls)
}

// popMarshal removes the ident from the messages that were marshalled but haven't found a sign for yet.
func (p *protoIntegrityChecker) popMarshal(id *ast.Ident) {
	idObj := p.pass.TypesInfo.Uses[id]
	delete(p.marshals, idObj)
}

// popUnmarshal removes the ident from the messages that were unmarshalled but haven't found a verify for yet.
func (p *protoIntegrityChecker) popUnmarshal(id *ast.Ident) {
	idObj := p.pass.TypesInfo.Uses[id]
	delete(p.unmarshalls, idObj)
}

// isBefore checks that the given idents tokenPos is located earlier in the code than the token position stored in the
// map for its underlying Object. This is used to check that a certain call using the object happened before this ident
// in the code.
func (p *protoIntegrityChecker) isBefore(id *ast.Ident, tokens map[types.Object]token.Pos) bool {
	idObj := p.pass.TypesInfo.Uses[id]
	// If it is in the map it is a type that needs to be signed/verified.
	marshalPos, ok := tokens[idObj]
	if !ok {
		// No token not found so marshal/unmarshal was not called on this ident.
		return true
	}
	return id.NamePos < marshalPos
}

func (p *protoIntegrityChecker) reportUnsignedMarshals() {
	for _, pos := range p.marshals {
		p.pass.Reportf(pos, "found possible marshalling of integrity proto before signing")
	}
}

func (p *protoIntegrityChecker) reportUnverifiedUnmarshals() {
	for _, pos := range p.unmarshalls {
		p.pass.Reportf(pos, "found possible unmarshalling of integrity proto without verifying afterwards")
	}
}

// Check for types which are imported which are generated protocol buffers with the message integrity option enabled
// and set to required, save these types for later use by the linter.
func (p *protoIntegrityChecker) checkImportsForIntegrityProtos(n ast.Node) bool {
	im, path, ok := getImportPath(n)
	if !ok {
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
			p.protoTypes[nt.String()] = *new(struct{})
			to := p.pass.TypesInfo.ObjectOf(im.Name)
			p.pass.ExportObjectFact(to, &integrityFact{t: *nt})
		}
	}
	return true
}

// checkSignsVerifies checks for Sign() and Verify() calls on integrity enabled idents and if they satisfy the
// requirements due to Marshals() or Unmarshal() then remove the objects referred to by the idents from the maps of
// unverified unmarshals and of unsigned marshals.
func (p *protoIntegrityChecker) checkSignsVerifies(n ast.Node) bool {
	sel, _, ok := castSelector(n)
	if !ok {
		return true
	}
	id := getIdent(sel.X)
	if id == nil {
		return true
	}
	switch sel.Sel.Name {
	case "Sign":
		if p.isMarshalledBefore(id) {
			// This sign was not before the marshal, keep looking.
			return true
		}
		// Remove marshal from set of candidate unsigned marshals.
		p.popMarshal(id)
	case "Verify":
		if p.isUnmarshalledAfter(id) {
			// This Verify was not after the marshal, keep looking.
			return true
		}
		// Remove unmarshal from set of candidate unverified unmarshalls.
		p.popUnmarshal(id)
	}
	return true
}

// findIntegrityProtos searches through the imports to find type names that have the integrity option set to required.
func (p *protoIntegrityChecker) findIntegrityProtos(packages []*loader.PackageInfo) (map[string]struct{}, error) {
	integrityProtoTypes := make(map[string]struct{})
	for _, p := range packages {
		for _, f := range p.Files {
			for _, d := range f.Scope.Objects {
				v, ok := castProtoRawDesc(d)
				if !ok {
					continue
				}
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
					_, ok := to.Decl.(*ast.TypeSpec)
					if !ok {
						return nil, errors.New("decl could not be converted to a typeSpec")
					}
					integrityProtoTypes[k] = *new(struct{})
				}
			}
		}
	}
	return integrityProtoTypes, nil
}

// isRequiredProto checks the map to see that the Expr is of a type that has the integrity option set to required.
func (p *protoIntegrityChecker) isRequiredProto(protoExpr ast.Expr) bool {
	t := p.pass.TypesInfo.TypeOf(protoExpr)
	_, ok := p.protoTypes[t.String()]
	return ok
}

const (
	MARSHAL   = "Marshal"
	UNMARSHAL = "Unmarshal"
)

// Find (Un)Marshals of integrity enabled protos.
func (p *protoIntegrityChecker) parseProtoMarshals(n ast.Node) bool {
	sel, args, ok := castSelector(n)
	if !ok {
		return true
	}
	// TODO(paulmolloy): Change to check the underlying src of the ident encase the import name was overridden to something else.
	if id := getIdent(sel.X); id == nil || strings.Compare(id.Name, "proto") != 0 {
		return true
	}
	// Take the proto message ident out of the args.
	var protoExpr ast.Expr
	switch sel.Sel.Name {
	case MARSHAL:
		// Want 1st of 1 params.
		if len(args) != 1 {
			return true
		}
		protoExpr = args[0]
	case UNMARSHAL:
		// Want 2nd of 2 params.
		if len(args) != 2 {
			return true
		}
		protoExpr = args[1]
	default:
		// It's some other func from proto and we don't care.
		return true
	}
	if !p.isRequiredProto(protoExpr) {
		return true
	}
	protoIdent, ok := castAddrOp(protoExpr)
	if !ok {
		return true
	}
	idObj, ok := p.pass.TypesInfo.Uses[protoIdent]
	if !ok {
		return true
	}
	to := p.pass.TypesInfo.ObjectOf(protoIdent)
	switch sel.Sel.Name {
	case MARSHAL:
		p.pass.ExportObjectFact(to, &integrityMarshalFact{})
		// Now we know it is an instance of a type we care about and it has been marshalled.
		// We need to check for a <ident>.Sign() just before.
		p.marshals[idObj] = protoExpr.Pos()
	case UNMARSHAL:
		p.pass.ExportObjectFact(to, &integrityUnmarshalFact{})
		// Now we know it is an instance of a type we care about and it has been unmarshalled.
		// We need to check for a <ident>.Verify() just after.
		p.unmarshalls[idObj] = protoExpr.Pos()
	}
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
