#!/bin/bash

mkdir -p internal/integritycheck/testdata/src/github.com/einride/protoc-gen-messageintegrity/proto/gen
mkdir -p internal/integritycheck/testdata/src/github.com/einride/protoc-gen-messageintegrity/internal/verification
mkdir -p internal/integritycheck/testdata/src/github.com/einride/protoc-gen-messageintegrity/internal/verificationoption
mkdir -p internal/integritycheck/testdata/src/github.com/einride/protoc-gen-messageintegrity/internal/verificationsymmetric
cp -r proto/gen/* internal/integritycheck/testdata/src/github.com/einride/protoc-gen-messageintegrity/proto/gen
cp -r internal/verification/* internal/integritycheck/testdata/src/github.com/einride/protoc-gen-messageintegrity/internal/verification
cp -r internal/verificationoption/* internal/integritycheck/testdata/src/github.com/einride/protoc-gen-messageintegrity/internal/verificationoption
cp -r internal/verificationsymmetric/* internal/integritycheck/testdata/src/github.com/einride/protoc-gen-messageintegrity/internal/verificationsymmetric

if [[ ! -d internal/integritycheck/testdata/src/github.com/golang/protobuf ]]
then
  git clone --depth=1 https://github.com/golang/protobuf internal/integritycheck/testdata/src/github.com/golang/protobuf
  rm -rf internal/integritycheck/testdata/src/github.com/golang/protobuf/.git
fi

if [[ ! -d internal/integritycheck/testdata/src/google.golang.org/protobuf ]]
then
  git clone --depth=1 https://github.com/protocolbuffers/protobuf-go internal/integritycheck/testdata/src/google.golang.org/protobuf/
  rm -rf internal/integritycheck/testdata/src/google.golang.org/protobuf/.git
fi
