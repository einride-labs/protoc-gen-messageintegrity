package verificationoption

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	integritypb "github.com/einride/protoc-gen-messageintegrity/proto/gen/integrity/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	"hash"
	"log"
)

const SignatureFieldName = "signature"
const ImplicitMessageIntegrityKey = "IMPLICIT_MESSAGE_INTEGRITY_KEY"

// VerifiableMessage a proto message that has a Signature field.
// Using the extension interface pattern so that I can read the Signature.
type VerifiableMessage interface {
	proto.Message
	GetSignature() []byte
	// Can't modify the Signature field since there is no Setters for proto-gen-go fields using protoreflect instead.
}

// Check the signature embedded in the protobuf message is correct for the message by recalculating
// it using the secret key.
func ValidateHMAC(message VerifiableMessage, key []byte) (bool, error) {
	if message == nil {
		return false, errors.New("message was nil")
	}
	if key == nil {
		return false, errors.New("key was nil")
	}
	// Some additional checks to really make sure it has a signature using reflection.

	receivedSig := message.GetSignature()

	// Using proto reflection to make this work as the field is not otherwise accessible without casting to
	// a specific type.
	signatureFieldDescriptor, err := retrieveSignatureFieldDescriptor(message)
	if err != nil {
		return false, err
	}
	opts := signatureFieldDescriptor.Options().(*descriptorpb.FieldOptions)
	sigOption := proto.GetExtension(opts, integritypb.E_MessageIntegritySignature).(*integritypb.MessageIntegritySignature)
	if sigOption == nil {
		return false, errors.New("signature not enabled for proto, no message integrity option; skipping checking")
	} else {
		fmt.Printf("else %v \n", sigOption.Behaviour)
	}
	if sigOption.Behaviour == integritypb.SignatureBehaviour_SIGNATURE_BEHAVIOUR_REQUIRED {
		if receivedSig == nil {
			return false, errors.New("signature behaviour required but signature not set")
		}
	}

	mac := hmac.New(sha256.New, key)
	// Calculate the expected signature
	sig, err := calculateSignature(message, mac)
	if err != nil {
		return false, err
	}
	return bytes.Equal(receivedSig, sig), nil
}

// SignProto signs a proto that has a proto field Signature.
func SignProto(message VerifiableMessage, key []byte) error {
	if message == nil {
		return errors.New("message was nil")
	}
	if key == nil {
		return errors.New("key was nil")
	}

	// Using proto reflection to make this work as the field is not otherwise accessible without casting to
	// a specific type.
	signatureFieldDescriptor, err := retrieveSignatureFieldDescriptor(message)
	if err != nil {
		return err
	}

	opts := signatureFieldDescriptor.Options().(*descriptorpb.FieldOptions)
	sigOption := proto.GetExtension(opts, integritypb.E_MessageIntegritySignature).(*integritypb.MessageIntegritySignature)
	if sigOption == nil {
		return errors.New("signature not enabled for proto, no message integrity option; skipping signing")
	} else {
		fmt.Printf("else %v\n", sigOption.Behaviour)
	}
	if sigOption.Behaviour == integritypb.SignatureBehaviour_SIGNATURE_BEHAVIOUR_UNSPECIFIED {
		return errors.New("signature not enabled for proto skipping signing")
	}

	if message.GetSignature() != nil {
		log.Printf("Signature for %v has already been set to re-signing...", signatureFieldDescriptor.FullName())
	}
	mac := hmac.New(sha256.New, key)
	sig, err := calculateSignature(message, mac)
	if err != nil {
		return err
	}
	// Assign the generated signature to the message using reflection as it is a VerifiableMessage and not cast to
	// its exact proto type.
	message.ProtoReflect().Set(signatureFieldDescriptor, protoreflect.ValueOfBytes(sig))
	log.Println(message.GetSignature())
	return nil
}

func retrieveSignatureFieldDescriptor(message VerifiableMessage) (protoreflect.FieldDescriptor, error) {
	signatureFieldDescriptor := message.ProtoReflect().Descriptor().Fields().ByName(SignatureFieldName)
	if signatureFieldDescriptor == nil {
		return nil,
			errors.New("message is not a verifiable message: it does not have a signature field")
	}
	signatureType := signatureFieldDescriptor.Kind()
	if signatureType != protoreflect.BytesKind {
		return nil,
			errors.New("message is not a verifiable message: has signature field but it is of type %v not bytes")
	}
	return signatureFieldDescriptor, nil
}

func calculateSignature(message VerifiableMessage, mac hash.Hash) ([]byte, error) {
	if message == nil {
		return nil, errors.New("message was nil")
	}
	signatureFieldDescriptor, err := retrieveSignatureFieldDescriptor(message)
	if err != nil {
		return nil, err
	}

	// Nil out the sig using reflection.
	message.ProtoReflect().Clear(signatureFieldDescriptor)
	// Marshal the message without a signature so that a sig can be generated for it.
	marshalled, err := proto.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto before signing: %v", err)
	}
	if _, err = mac.Write(marshalled); err != nil {
		return nil, err
	}
	// Return the generated signature.
	return mac.Sum(nil), nil
}
