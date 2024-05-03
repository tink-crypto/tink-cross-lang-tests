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

package services

import (
	"context"

	"github.com/tink-crypto/tink-go/v2/signature"
	pb "github.com/tink-crypto/tink-cross-lang-tests/go/protos/testing_api_go_grpc"
)

// SignatureService implements the Signature testing service.
type SignatureService struct {
	pb.SignatureServer
}

func (s *SignatureService) CreatePublicKeySign(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	handle, err := toKeysetHandle(req.GetAnnotatedKeyset())
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = signature.NewSigner(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *SignatureService) CreatePublicKeyVerify(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	handle, err := toKeysetHandle(req.GetAnnotatedKeyset())
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = signature.NewVerifier(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *SignatureService) Sign(ctx context.Context, req *pb.SignatureSignRequest) (*pb.SignatureSignResponse, error) {
	handle, err := toKeysetHandle(req.GetPrivateAnnotatedKeyset())
	if err != nil {
		return &pb.SignatureSignResponse{
			Result: &pb.SignatureSignResponse_Err{err.Error()}}, nil
	}
	signer, err := signature.NewSigner(handle)
	if err != nil {
		return &pb.SignatureSignResponse{
			Result: &pb.SignatureSignResponse_Err{err.Error()}}, nil
	}
	sigValue, err := signer.Sign(req.Data)
	if err != nil {
		return &pb.SignatureSignResponse{
			Result: &pb.SignatureSignResponse_Err{err.Error()}}, nil
	}
	return &pb.SignatureSignResponse{
		Result: &pb.SignatureSignResponse_Signature{sigValue}}, nil
}

func (s *SignatureService) Verify(ctx context.Context, req *pb.SignatureVerifyRequest) (*pb.SignatureVerifyResponse, error) {
	handle, err := toKeysetHandle(req.GetPublicAnnotatedKeyset())
	if err != nil {
		return &pb.SignatureVerifyResponse{Err: err.Error()}, nil
	}
	verifier, err := signature.NewVerifier(handle)
	if err != nil {
		return &pb.SignatureVerifyResponse{Err: err.Error()}, nil
	}
	err = verifier.Verify(req.Signature, req.Data)
	if err != nil {
		return &pb.SignatureVerifyResponse{Err: err.Error()}, nil
	}
	return &pb.SignatureVerifyResponse{}, nil
}
