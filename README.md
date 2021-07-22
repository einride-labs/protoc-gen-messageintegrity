# Implicit Message Integrity 

Code for the thesis "Implicit Message Integrity in Heterogeneous Systems".

    This library provides a plugin to protocol buffer go complier [github.com/golang/protobuf][protoc-gen-go] to allow automatic generation of code for signing and verification of Protocol Buffer messages.


## Installing

```bash
go get -u github.com/einride/protoc-gen-messageintegrity
```

# Running
``` make 
buf-generate: $(buf) $(protoc) $(protoc_gen_go) $(protoc_gen_message_integrity) build-plugin
```
## Example
By adding the custom option integrity.v1.signature to a field of a message the plugin will know to add signing and verification methods to the generated type:
``` proto
message SteeringCommand {
    float steering_angle = 1;
    bytes signature = 2 [(integrity.v1.signature) = {
      behaviour: SIGNATURE_BEHAVIOUR_REQUIRED,
        }];
}
```
This will create a file proto_file_name.message_integrity.go with Sign() and Verify() receiver methods beside the proto_file_name.pb.go:
```go
...
func (x *SteeringCommandVerification) Sign() error {
	keyID := os.Getenv(ImplicitMessageIntegrityKeyID)
	return verificationRsaOption.SignPKCS1v15(x, verificationRsaOption.KeyID(keyID))
}

func (x *SteeringCommandVerification) Verify() (bool, error) {
	keyID := os.Getenv(ImplicitMessageIntegrityKeyID)
	return verificationRsaOption.ValidatePKCS1v15(x, verificationRsaOption.KeyID(keyID))
}
...
```

Then to sign a message before it is marhsalled a developer writes:

```go
msg.Sign()
proto.Marshall(msg)
```
To Verify a message after it is unmarshalled the following is required:

```go
proto.Unmarshall(bytes, &msg)
if ok, err := msg.Verify(); !ok || err != nil {
	// Signature does not match
}
```
### Message Integrity Linter

Additionally a custom linter to ensure correct use of the message integrity plugin was created.
It detects if any proto types which have the option enabled are not signed or verified before marshalling or after unmarhsalling respectively.

#### Building
``` make
build-integritylint:
	@go build -o bin/integritylint cmd/integritylint/main.go
```
#### Running
integritylint: build-integritylint
	./bin/integritylint go_file.go
