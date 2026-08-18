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

package services_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-cross-lang-tests/go/services"
	pb "github.com/tink-crypto/tink-cross-lang-tests/go/protos/testing_api_go_grpc"
)

func serializeKeyset(t *testing.T, handle *keyset.Handle) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(buf)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	return buf.Bytes()
}

func privateKeysetHandle(t *testing.T) *keyset.Handle {
	t.Helper()
	params, err := tinkmldsa.NewParameters(tinkmldsa.MLDSA65, tinkmldsa.VariantNoPrefixWithPrehashID)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters() err = %v, want nil", err)
	}
	manager := keyset.NewManager()
	keyID, err := manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters() err = %v, want nil", err)
	}
	if err := manager.SetPrimary(keyID); err != nil {
		t.Fatalf("manager.SetPrimary() err = %v, want nil", err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	return handle
}

func publicKeysetHandle(t *testing.T, privateHandle *keyset.Handle) *keyset.Handle {
	t.Helper()
	publicHandle, err := privateHandle.Public()
	if err != nil {
		t.Fatalf("privateHandle.Public() err = %v, want nil", err)
	}
	return publicHandle
}

func TestCreatePrehashSuccess(t *testing.T) {
	ctx := context.Background()
	s := &services.SignPrehashService{}

	privateHandle := privateKeysetHandle(t)
	publicHandle := publicKeysetHandle(t, privateHandle)

	req := &pb.CreationRequest{
		AnnotatedKeyset: &pb.AnnotatedKeyset{
			SerializedKeyset: serializeKeyset(t, publicHandle),
		},
	}
	resp, err := s.CreatePrehash(ctx, req)
	if err != nil {
		t.Fatalf("CreatePrehash() err = %v, want nil", err)
	}
	if resp.GetErr() != "" {
		t.Errorf("CreatePrehash() response err = %q, want empty", resp.GetErr())
	}
}

func TestCreatePrehashFailure(t *testing.T) {
	ctx := context.Background()
	s := &services.SignPrehashService{}

	req := &pb.CreationRequest{
		AnnotatedKeyset: &pb.AnnotatedKeyset{
			SerializedKeyset: []byte{0x80},
		},
	}
	resp, err := s.CreatePrehash(ctx, req)
	if err != nil {
		t.Fatalf("CreatePrehash() err = %v, want nil", err)
	}
	if resp.GetErr() == "" {
		t.Errorf("CreatePrehash() response err is empty, want non-empty")
	}
}

func TestCreatePrehashSignerSuccess(t *testing.T) {
	ctx := context.Background()
	s := &services.SignPrehashService{}

	privateHandle := privateKeysetHandle(t)

	req := &pb.CreationRequest{
		AnnotatedKeyset: &pb.AnnotatedKeyset{
			SerializedKeyset: serializeKeyset(t, privateHandle),
		},
	}
	resp, err := s.CreatePrehashSigner(ctx, req)
	if err != nil {
		t.Fatalf("CreatePrehashSigner() err = %v, want nil", err)
	}
	if resp.GetErr() != "" {
		t.Errorf("CreatePrehashSigner() response err = %q, want empty", resp.GetErr())
	}
}

func TestCreatePrehashSignerFailure(t *testing.T) {
	ctx := context.Background()
	s := &services.SignPrehashService{}

	req := &pb.CreationRequest{
		AnnotatedKeyset: &pb.AnnotatedKeyset{
			SerializedKeyset: []byte{0x80},
		},
	}
	resp, err := s.CreatePrehashSigner(ctx, req)
	if err != nil {
		t.Fatalf("CreatePrehashSigner() err = %v, want nil", err)
	}
	if resp.GetErr() == "" {
		t.Errorf("CreatePrehashSigner() response err is empty, want non-empty")
	}
}

func TestComputeAndSignPrehashSuccess(t *testing.T) {
	ctx := context.Background()
	s := &services.SignPrehashService{}

	privateHandle := privateKeysetHandle(t)
	publicHandle := publicKeysetHandle(t, privateHandle)

	computeReq := &pb.ComputePrehashRequest{
		PublicAnnotatedKeyset: &pb.AnnotatedKeyset{
			SerializedKeyset: serializeKeyset(t, publicHandle),
		},
		Data: []byte("some data to prehash"),
	}
	computeResp, err := s.ComputePrehash(ctx, computeReq)
	if err != nil {
		t.Fatalf("ComputePrehash() err = %v, want nil", err)
	}
	if computeResp.GetErr() != "" {
		t.Fatalf("ComputePrehash() response err = %q, want empty", computeResp.GetErr())
	}
	if len(computeResp.GetPrehash()) == 0 {
		t.Errorf("ComputePrehash() response prehash is empty, want non-empty")
	}

	signReq := &pb.SignPrehashRequest{
		PrivateAnnotatedKeyset: &pb.AnnotatedKeyset{
			SerializedKeyset: serializeKeyset(t, privateHandle),
		},
		Prehash: computeResp.GetPrehash(),
	}
	signResp, err := s.SignPrehash(ctx, signReq)
	if err != nil {
		t.Fatalf("SignPrehash() err = %v, want nil", err)
	}
	if signResp.GetErr() != "" {
		t.Fatalf("SignPrehash() response err = %q, want empty", signResp.GetErr())
	}
	if len(signResp.GetSignature()) == 0 {
		t.Errorf("SignPrehash() response signature is empty, want non-empty")
	}
}
