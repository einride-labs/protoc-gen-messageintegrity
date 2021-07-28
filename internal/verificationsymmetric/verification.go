package verificationsymmetric

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	integritypb "github.com/einride/protoc-gen-messageintegrity/proto/gen/integrity/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	"hash"
	"log"
	"os"
)

type KeyID string

type signatureProtocol int

const (
	HMACSHA256 signatureProtocol = iota
	RSAPKCS1v15SHA256
)

const ImplicitMessageIntegrityKey = "IMPLICIT_MESSAGE_INTEGRITY_KEY"
const ImplicitMessageIntegrityPublicKey = "IMPLICIT_MESSAGE_INTEGRITY_PUBLIC_KEY"
const ImplicitMessageIntegrityPrivateKey = "IMPLICIT_MESSAGE_INTEGRITY_PRIVATE_KEY"
const DefaultKeysDir = "integrity-keys"

// VerifiableMessage a proto message that has a Signature field.
// Using the extension interface pattern so that I can read the Signature.
type VerifiableMessage interface {
	proto.Message
	GetSignature() []byte
	// Can't modify the Signature field since there is no Setters for proto-gen-go fields using protoreflect instead.
}

func ValidatePKCS1v15(message VerifiableMessage, keyID KeyID) (bool, error) {
	if message == nil {
		return false, errors.New("message was nil")
	}

	signatureFieldDescriptor, err := retrieveSignatureFieldDescriptor(message)
	if err != nil {
		return false, err
	}
	receivedSig := message.ProtoReflect().Get(signatureFieldDescriptor).Bytes()
	if receivedSig == nil {
		return false, errors.New("signature behaviour required but signature not set")
	}
	protocol := RSAPKCS1v15SHA256
	var sig []byte
	switch protocol {
	case RSAPKCS1v15SHA256:
		publicKey, err := FetchPublicKey(keyID)
		if err != nil {
			return false, fmt.Errorf("public key not found for key: %v", keyID)
		}
		// Returns an error if they don't match.
		_, err = verifySignaturePKCS1v15(message, publicKey, receivedSig)
		if err != nil {
			if err.Error() == "crypto/rsa: verification error" {
				return false, nil
			}
			return false, err
		}
		return true, nil
	case HMACSHA256:
	default:
		key := []byte(os.Getenv(ImplicitMessageIntegrityKey))
		if key == nil {
			return false, errors.New("key was nil")
		}
		mac := hmac.New(sha256.New, []byte(key))
		// Calculate the expected signature
		sig, err = calculateSignature(message, mac)
		if err != nil {
			return false, err
		}
		return bytes.Equal(receivedSig, sig), nil
	}
	return true, nil
}

// SignProto signs a proto that has a proto field Signature.
func SignPKCS1v15(message VerifiableMessage, keyID KeyID) error {
	if message == nil {
		return errors.New("message was nil")
	}
	// Using proto reflection to make this work as the field is not otherwise accessible without casting to
	// a specific type.
	signatureFieldDescriptor, err := retrieveSignatureFieldDescriptor(message)
	if err != nil {
		return err
	}

	if message.ProtoReflect().Get(signatureFieldDescriptor).Bytes() != nil {
		log.Printf("Signature for %v has already been set to re-signing...", signatureFieldDescriptor.FullName())
	}
	protocol := RSAPKCS1v15SHA256
	var sig []byte
	switch protocol {
	case RSAPKCS1v15SHA256:
		privateKey, err := FetchPrivateKey(keyID)
		if err != nil {
			return fmt.Errorf("private key not found for key: %v", keyID)
		}
		sig, err = calculateSignaturePKCS1v15(message, privateKey)
		if err != nil {
			return err
		}

	case HMACSHA256:
	default:
		key := []byte(os.Getenv(ImplicitMessageIntegrityKey))
		if key == nil {
			return errors.New("key was nil")
		}
		mac := hmac.New(sha256.New, key)
		sig, err = calculateSignature(message, mac)
		if err != nil {
			return err
		}
	}
	// Assign the generated signature to the message using reflection as it is a VerifiableMessage and not cast to
	// its exact proto type.
	message.ProtoReflect().Set(signatureFieldDescriptor, protoreflect.ValueOfBytes(sig))
	return nil
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
	signatureFieldDescriptor, err := retrieveSignatureFieldDescriptor(message)
	if err != nil {
		return false, err
	}
	receivedSig := message.ProtoReflect().Get(signatureFieldDescriptor).Bytes()
	if receivedSig == nil {
		return false, errors.New("signature behaviour required but signature not set")
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

	if message.ProtoReflect().Get(signatureFieldDescriptor).Bytes() != nil {
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
	return nil
}

// retrieveSignatureFieldDescriptor finds the field where the signature is stored in the message
func retrieveSignatureFieldDescriptor(message VerifiableMessage) (protoreflect.FieldDescriptor, error) {
	m := message.ProtoReflect()
	// Can't use Range() as we can't identify signatures that have not been signed as it skips unset fields.
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.Kind() != protoreflect.BytesKind {
			continue // The signature can only be a bytes field, ignore everything else.
		}
		opts := fd.Options().(*descriptorpb.FieldOptions)
		sigOption, ok := proto.GetExtension(opts, integritypb.E_Signature).(*integritypb.Signature)
		if !ok ||  sigOption.GetBehaviour() == integritypb.SignatureBehaviour_SIGNATURE_BEHAVIOUR_UNSPECIFIED {
			// Failed to find or cast a MessageIntegrityOption, keep looking.
			continue
		}
		// Only check the first instance of a signature option field.
		// TODO(paulmolloy): Change to fail if there are multiple signature options in a message.
		return fd, nil
	}
	return nil, errors.New("failed to find any message integrity signature field in proto")
}

// Marshal the message without a signature so that a sig can be generated for it.
func prepMessageForSigning(message VerifiableMessage) ([]byte, error) {
	if message == nil {
		return nil, errors.New("message was nil")
	}
	signatureFieldDescriptor, err := retrieveSignatureFieldDescriptor(message)
	if err != nil {
		return nil, err
	}
	// Nil out the sig using reflection.
	messageCopy := proto.Clone(message)
	messageCopy.ProtoReflect().Clear(signatureFieldDescriptor)
	// Marshal the message without a signature so that a sig can be generated for it.
	marshalled, err := proto.Marshal(messageCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto before signing: %v", err)
	}
	return marshalled, nil
}

func calculateSignature(message VerifiableMessage, mac hash.Hash) ([]byte, error) {
	data, err := prepMessageForSigning(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto before signing: %v", err)
	}
	if _, err = mac.Write(data); err != nil {
		return nil, err
	}
	// Return the generated signature.
	return mac.Sum(nil), nil
}

func calculateSignaturePKCS1v15(message VerifiableMessage, privateKey *rsa.PrivateKey) ([]byte, error) {
	data, err := prepMessageForSigning(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto before signing: %v", err)
	}
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	// Return the generated signature.
	return signature, nil
}

func verifySignaturePKCS1v15(message VerifiableMessage, publicKey *rsa.PublicKey, signature []byte) ([]byte, error) {
	data, err := prepMessageForSigning(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proto before signing: %v", err)
	}
	hashed := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return nil, err
	}
	// Return the generated signature.
	return signature, nil
}
