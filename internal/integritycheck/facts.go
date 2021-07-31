package integritycheck

import (
	"fmt"
	"go/types"
)

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

type integrityMarshalFact struct {
}

func (i *integrityMarshalFact) String() string {
	return "found marshal of message integrity enabled proto message"
}
func (*integrityMarshalFact) AFact() {}

type integrityUnmarshalFact struct {
}

func (i *integrityUnmarshalFact) String() string {
	return "found unmarshal of message integrity enabled proto message"
}
func (*integrityUnmarshalFact) AFact() {}

