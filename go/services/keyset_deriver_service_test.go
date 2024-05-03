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

package services_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyderivation"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/prf"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-cross-lang-tests/go/services"
	pb "github.com/tink-crypto/tink-cross-lang-tests/go/protos/testing_api_go_grpc"
)

func TestSuccessfulDeriverCreation(t *testing.T) {
	ctx := context.Background()

	template, err := keyderivation.CreatePRFBasedKeyTemplate(prf.HKDFSHA256PRFKeyTemplate(), aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyderivation.CreatePRFBasedKeyTemplate() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	serializedHandle := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(serializedHandle)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}

	s := &services.KeysetDeriverService{}
	result, err := s.Create(ctx, &pb.CreationRequest{AnnotatedKeyset: &pb.AnnotatedKeyset{SerializedKeyset: serializedHandle.Bytes()}})
	if err != nil {
		t.Fatalf("Create with good keyset failed with gRPC error: %v", err)
	}
	if result.GetErr() != "" {
		t.Fatalf("Create with good keyset failed with creation error: %v", result.GetErr())
	}
}

func TestFailingDeriverCreation(t *testing.T) {
	ctx := context.Background()

	s := &services.KeysetDeriverService{}
	result, err := s.Create(ctx, &pb.CreationRequest{
		AnnotatedKeyset: &pb.AnnotatedKeyset{SerializedKeyset: []byte{0x80}}})
	if err != nil {
		t.Fatalf("Create with bad keyset failed with gRPC error: %v", err)
	}
	if result.GetErr() == "" {
		t.Fatalf("Create with bad keyset succeeded instead of failing")
	}
}

func TestDeriveKeyset(t *testing.T) {
	template, err := keyderivation.CreatePRFBasedKeyTemplate(prf.HKDFSHA256PRFKeyTemplate(), aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyderivation.CreatePRFBasedKeyTemplate() err = %v, want nil", err)
	}
	handle, err := keyset.NewHandle(template)
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	salt := "salty"

	// Derive keyset handle using KeysetDeriverService.
	ctx := context.Background()
	s := &services.KeysetDeriverService{}
	serializedHandle := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(serializedHandle)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}
	req := &pb.DeriveKeysetRequest{
		AnnotatedKeyset: &pb.AnnotatedKeyset{
			SerializedKeyset: serializedHandle.Bytes(),
		},
		Salt: []byte(salt),
	}
	resp, err := s.DeriveKeyset(ctx, req)
	if err != nil {
		t.Fatalf("DeriveKeyset() err = %v, want nil", err)
	}
	serviceDerivedHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(resp.GetDerivedKeyset())))
	if err != nil {
		t.Fatalf("insecurecleartextkeyset.Read() err = %v, want nil", err)
	}

	// Derive keyset handle using KeysetDeriver factory.
	kd, err := keyderivation.New(handle)
	if err != nil {
		t.Fatalf("keyderivation.New() err = %v, want nil", err)
	}
	factoryDerivedHandle, err := kd.DeriveKeyset([]byte(salt))
	if err != nil {
		t.Fatalf("DeriveKeyset() err = %v, want nil", err)
	}

	// Verify the derived keyset handles can encrypt, decrypt each other's output.
	serviceAEAD, err := aead.New(serviceDerivedHandle)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	factoryAEAD, err := aead.New(factoryDerivedHandle)
	if err != nil {
		t.Fatalf("aead.New() err = %v, want nil", err)
	}
	pt := random.GetRandomBytes(16)
	ad := random.GetRandomBytes(4)
	{
		ct, err := serviceAEAD.Encrypt(pt, ad)
		if err != nil {
			t.Fatalf("Encrypt() err = %v, want nil", err)
		}
		gotPT, err := factoryAEAD.Decrypt(ct, ad)
		if err != nil {
			t.Fatalf("Decrypt() err = %v, want nil", err)
		}
		if !bytes.Equal(gotPT, pt) {
			t.Errorf("Decrypt() = %v, want %v", gotPT, pt)
		}
	}
	{
		ct, err := factoryAEAD.Encrypt(pt, ad)
		if err != nil {
			t.Fatalf("Encrypt() err = %v, want nil", err)
		}
		gotPT, err := serviceAEAD.Decrypt(ct, ad)
		if err != nil {
			t.Fatalf("Decrypt() err = %v, want nil", err)
		}
		if !bytes.Equal(gotPT, pt) {
			t.Errorf("Decrypt() = %v, want %v", gotPT, pt)
		}
	}
}

func TestDeriveKeysetFails(t *testing.T) {
	wrongTypeHandle, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() err = %v, want nil", err)
	}
	serializedWrongTypeHandle := &bytes.Buffer{}
	if err := insecurecleartextkeyset.Write(wrongTypeHandle, keyset.NewBinaryWriter(serializedWrongTypeHandle)); err != nil {
		t.Fatalf("insecurecleartextkeyset.Write() err = %v, want nil", err)
	}

	for _, test := range []struct {
		name   string
		keyset []byte
	}{
		{
			name: "nil keyset",
		},
		{
			name:   "malformed keyset",
			keyset: random.GetRandomBytes(32),
		},
		{
			name:   "keyset with wrong key type",
			keyset: serializedWrongTypeHandle.Bytes(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			s := &services.KeysetDeriverService{}
			req := &pb.DeriveKeysetRequest{
				AnnotatedKeyset: &pb.AnnotatedKeyset{
					SerializedKeyset: test.keyset,
				},
				Salt: []byte("salty"),
			}
			resp, err := s.DeriveKeyset(ctx, req)
			if err != nil {
				t.Errorf("DeriveKeyset() err = %v, want nil", err)
			}
			if resp.GetErr() == "" {
				t.Errorf("DeriveKeyset() = \"\", want error string")
			}
		})
	}
}
