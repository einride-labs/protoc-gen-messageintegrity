package plugin

import (
	"bytes"
	"fmt"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/pluginpb"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type MessageIntegrityPlugin struct {
	*protogen.Plugin
}

func (g *MessageIntegrityPlugin) Generate() error {
	log.Println("Hello Implicit Message Integrity plugin")
	// Good reference tutorial here:
	// https://medium.com/@tim.r.coulson/writing-a-protoc-plugin-with-google-golang-org-protobuf-cd5aa75f5777

	// Protoc passes this a pluginpb.CodeGeneratorRequest to stdin.
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	var req pluginpb.CodeGeneratorRequest
	if err = proto.Unmarshal(data, &req); err != nil {
		return err
	}

	// Init the plugin.

	opts := protogen.Options{}
	plugin, err := opts.New(&req)
	if err != nil {
		return err
	}
	// Iterate through the file structs from protoc.
	for _, file := range plugin.Files {
		// Generate code in here to a buffer.
		var buf bytes.Buffer
		// Write autogen warning.
		buf.Write([]byte("// Code generated by protoc-gen-messageintegrity. DO NOT EDIT.\n"))
		buf.Write([]byte("// versions: \n"))
		buf.Write([]byte("//  protoc-gen-messageintegrity	v0.1.0\n"))
		buf.Write([]byte(fmt.Sprintf(
			"//  protoc						v%v.%v.%v\n",
			req.CompilerVersion.GetMajor(),
			req.CompilerVersion.GetMinor(),
			req.CompilerVersion.GetPatch(),
		)))
		buf.Write([]byte(fmt.Sprintf("// source: %v.\n\n", file.Desc.Path())))

		// Write package name.
		buf.Write([]byte(fmt.Sprintf("package %s\n", file.GoPackageName)))

		buf.Write([]byte(`const ImplicitMessageIntegrityKey = "IMPLICIT_MESSAGE_INTEGRITY_KEY"`))
		// Go through each message if it has a signature field give it sign and verify methods.
		hasSignatureField := false
		for _, msg := range file.Proto.MessageType {
			for _, field := range msg.GetField() {
				if strings.Compare(*field.Name, "signature") == 0 {
					hasSignatureField = true
				}
			}
			// Only add the signature verification methods if the message has the Signature field.
			if hasSignatureField {
				buf.Write([]byte(fmt.Sprintf(`


func (x *%s) Sign() error {
	key := os.Getenv(ImplicitMessageIntegrityKey)
	return verification.SignProto(x, []byte(key))
}

func (x *%s) Verify() (bool, error) {
	key := os.Getenv(ImplicitMessageIntegrityKey)
	return verification.ValidateHMAC(x, []byte(key))
}

`, *msg.Name, *msg.Name)))
			}

		}
		// Set output file.
		filename := file.GeneratedFilenamePrefix + ".messageintegrity.go"
		file := plugin.NewGeneratedFile(filename, ".")
		file.QualifiedGoIdent(protogen.GoIdent{GoName: "os", GoImportPath: "os"})
		file.QualifiedGoIdent(protogen.GoIdent{

			GoName:       "github.com/einride/protoc-gen-messageintegrity/internal/verification",
			GoImportPath: "github.com/einride/protoc-gen-messageintegrity/internal/verification",
		})

		// Write file.
		if _, err = file.Write(buf.Bytes()); err != nil {
			return err
		}
		// Generate a response from the plugin and marshal and send via stdout.
		stdout := plugin.Response()
		out, err := proto.Marshal(stdout)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stdout, string(out))
	}
	return nil
}
