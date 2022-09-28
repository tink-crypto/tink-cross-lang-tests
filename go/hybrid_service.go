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
	"bytes"
	"context"

	"github.com/tink-crypto/tink-go/hybrid"
	"github.com/tink-crypto/tink-go/keyset"
	"github.com/tink-crypto/tink-go/insecurecleartextkeyset"
	pb "github.com/tink-crypto/tink-cross-lang-tests/go/proto/testing_api_go_grpc"
)

// HybridService implements the Hybrid encryption and decryption testing service.
type HybridService struct {
	pb.HybridServer
}

func (s *HybridService) CreateHybridEncrypt(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = hybrid.NewHybridEncrypt(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *HybridService) CreateHybridDecrypt(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = hybrid.NewHybridDecrypt(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *HybridService) Encrypt(ctx context.Context, req *pb.HybridEncryptRequest) (*pb.HybridEncryptResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.PublicKeyset))
	handle, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return &pb.HybridEncryptResponse{
			Result: &pb.HybridEncryptResponse_Err{err.Error()}}, nil
	}
	cipher, err := hybrid.NewHybridEncrypt(handle)
	if err != nil {
		return &pb.HybridEncryptResponse{
			Result: &pb.HybridEncryptResponse_Err{err.Error()}}, nil
	}
	ciphertext, err := cipher.Encrypt(req.Plaintext, req.ContextInfo)
	if err != nil {
		return &pb.HybridEncryptResponse{
			Result: &pb.HybridEncryptResponse_Err{err.Error()}}, nil
	}
	return &pb.HybridEncryptResponse{
		Result: &pb.HybridEncryptResponse_Ciphertext{ciphertext}}, nil
}

func (s *HybridService) Decrypt(ctx context.Context, req *pb.HybridDecryptRequest) (*pb.HybridDecryptResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.PrivateKeyset))
	handle, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return &pb.HybridDecryptResponse{
			Result: &pb.HybridDecryptResponse_Err{err.Error()}}, nil
	}
	cipher, err := hybrid.NewHybridDecrypt(handle)
	if err != nil {
		return &pb.HybridDecryptResponse{
			Result: &pb.HybridDecryptResponse_Err{err.Error()}}, nil
	}
	plaintext, err := cipher.Decrypt(req.Ciphertext, req.ContextInfo)
	if err != nil {
		return &pb.HybridDecryptResponse{
			Result: &pb.HybridDecryptResponse_Err{err.Error()}}, nil
	}
	return &pb.HybridDecryptResponse{
		Result: &pb.HybridDecryptResponse_Plaintext{plaintext}}, nil
}
