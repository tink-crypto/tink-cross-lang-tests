// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package services

import (
	"context"

	"github.com/tink-crypto/tink-go/v2/daead"
	pb "github.com/tink-crypto/tink-cross-lang-tests/go/protos/testing_api_go_grpc"
)

// DeterministicAEADService implements the DeterministicAead testing service.
type DeterministicAEADService struct {
	pb.DeterministicAeadServer
}

func (s *DeterministicAEADService) Create(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	handle, err := toKeysetHandle(req.GetAnnotatedKeyset())
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = daead.New(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *DeterministicAEADService) EncryptDeterministically(ctx context.Context, req *pb.DeterministicAeadEncryptRequest) (*pb.DeterministicAeadEncryptResponse, error) {
	handle, err := toKeysetHandle(req.GetAnnotatedKeyset())
	if err != nil {
		return nil, err
	}
	cipher, err := daead.New(handle)
	if err != nil {
		return nil, err
	}
	ciphertext, err := cipher.EncryptDeterministically(req.Plaintext, req.AssociatedData)
	if err != nil {
		return &pb.DeterministicAeadEncryptResponse{
			Result: &pb.DeterministicAeadEncryptResponse_Err{err.Error()}}, nil
	}
	return &pb.DeterministicAeadEncryptResponse{
		Result: &pb.DeterministicAeadEncryptResponse_Ciphertext{ciphertext}}, nil
}

func (s *DeterministicAEADService) DecryptDeterministically(ctx context.Context, req *pb.DeterministicAeadDecryptRequest) (*pb.DeterministicAeadDecryptResponse, error) {
	handle, err := toKeysetHandle(req.GetAnnotatedKeyset())
	if err != nil {
		return nil, err
	}
	cipher, err := daead.New(handle)
	if err != nil {
		return nil, err
	}
	plaintext, err := cipher.DecryptDeterministically(req.Ciphertext, req.AssociatedData)
	if err != nil {
		return &pb.DeterministicAeadDecryptResponse{
			Result: &pb.DeterministicAeadDecryptResponse_Err{err.Error()}}, nil
	}
	return &pb.DeterministicAeadDecryptResponse{
		Result: &pb.DeterministicAeadDecryptResponse_Plaintext{plaintext}}, nil
}
