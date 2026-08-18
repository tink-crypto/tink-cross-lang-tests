// Copyright 2026 Google LLC
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

	"github.com/tink-crypto/tink-go/v2/signprehash"
	pb "github.com/tink-crypto/tink-cross-lang-tests/go/protos/testing_api_go_grpc"
)

// SignPrehashService implements the SignPrehash testing service.
type SignPrehashService struct {
	pb.SignPrehashServer
}

func (s *SignPrehashService) CreatePrehash(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	handle, err := toKeysetHandle(req.GetAnnotatedKeyset())
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = signprehash.NewPrehash(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *SignPrehashService) CreatePrehashSigner(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	handle, err := toKeysetHandle(req.GetAnnotatedKeyset())
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = signprehash.NewPrehashSigner(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *SignPrehashService) ComputePrehash(ctx context.Context, req *pb.ComputePrehashRequest) (*pb.ComputePrehashResponse, error) {
	handle, err := toKeysetHandle(req.GetPublicAnnotatedKeyset())
	if err != nil {
		return &pb.ComputePrehashResponse{
			Result: &pb.ComputePrehashResponse_Err{Err: err.Error()}}, nil
	}
	prehasher, err := signprehash.NewPrehash(handle)
	if err != nil {
		return &pb.ComputePrehashResponse{
			Result: &pb.ComputePrehashResponse_Err{Err: err.Error()}}, nil
	}
	prehashVal, err := prehasher.ComputePrehash(req.Data)
	if err != nil {
		return &pb.ComputePrehashResponse{
			Result: &pb.ComputePrehashResponse_Err{Err: err.Error()}}, nil
	}
	return &pb.ComputePrehashResponse{
		Result: &pb.ComputePrehashResponse_Prehash{Prehash: prehashVal}}, nil
}

func (s *SignPrehashService) SignPrehash(ctx context.Context, req *pb.SignPrehashRequest) (*pb.SignPrehashResponse, error) {
	handle, err := toKeysetHandle(req.GetPrivateAnnotatedKeyset())
	if err != nil {
		return &pb.SignPrehashResponse{
			Result: &pb.SignPrehashResponse_Err{Err: err.Error()}}, nil
	}
	signer, err := signprehash.NewPrehashSigner(handle)
	if err != nil {
		return &pb.SignPrehashResponse{
			Result: &pb.SignPrehashResponse_Err{Err: err.Error()}}, nil
	}
	sigValue, err := signer.SignPrehash(req.Prehash)
	if err != nil {
		return &pb.SignPrehashResponse{
			Result: &pb.SignPrehashResponse_Err{Err: err.Error()}}, nil
	}
	return &pb.SignPrehashResponse{
		Result: &pb.SignPrehashResponse_Signature{Signature: sigValue}}, nil
}
