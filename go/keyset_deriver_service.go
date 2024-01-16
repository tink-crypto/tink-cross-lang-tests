// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// /////////////////////////////////////////////////////////////////////////////

package services

import (
	"bytes"
	"context"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyderivation"
	"github.com/tink-crypto/tink-go/v2/keyset"
	pb "github.com/tink-crypto/tink-cross-lang-tests/go/protos/testing_api_go_grpc"
)

// KeysetDeriverService implements the KeysetDeriver testing service.
type KeysetDeriverService struct {
	pb.KeysetDeriverServer
}

func (s *KeysetDeriverService) Create(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	handle, err := toKeysetHandle(req.GetAnnotatedKeyset())
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = keyderivation.New(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func deriveKeysetResponseError(err error) *pb.DeriveKeysetResponse {
	return &pb.DeriveKeysetResponse{
		Result: &pb.DeriveKeysetResponse_Err{err.Error()},
	}
}

func (s *KeysetDeriverService) DeriveKeyset(ctx context.Context, req *pb.DeriveKeysetRequest) (*pb.DeriveKeysetResponse, error) {
	handle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(req.GetAnnotatedKeyset().GetSerializedKeyset())))
	if err != nil {
		return deriveKeysetResponseError(err), nil
	}
	deriver, err := keyderivation.New(handle)
	if err != nil {
		return deriveKeysetResponseError(err), nil
	}
	derivedHandle, err := deriver.DeriveKeyset(req.GetSalt())
	if err != nil {
		return deriveKeysetResponseError(err), nil
	}
	serializedDerivedHandle := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(derivedHandle, keyset.NewBinaryWriter(serializedDerivedHandle)); err != nil {
		return deriveKeysetResponseError(err), nil
	}
	return &pb.DeriveKeysetResponse{
		Result: &pb.DeriveKeysetResponse_DerivedKeyset{serializedDerivedHandle.Bytes()},
	}, nil
}
