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
//
///////////////////////////////////////////////////////////////////////////////

#include "sign_prehash_impl.h"

#include <memory>
#include <ostream>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "tink/signature/key_gen_config_2026.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "protos/testing_api.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;

using ::testing::IsEmpty;
using ::testing::Not;

using ::tink_testing_api::ComputePrehashRequest;
using ::tink_testing_api::ComputePrehashResponse;
using ::tink_testing_api::CreationRequest;
using ::tink_testing_api::CreationResponse;
using ::tink_testing_api::SignPrehashImpl;
using ::tink_testing_api::SignPrehashRequest;
using ::tink_testing_api::SignPrehashResponse;

using crypto::tink::KeysetHandle;

std::string KeysetBytes(const KeysetHandle& keyset_handle) {
  std::stringbuf keyset;
  absl::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer_result =
      BinaryKeysetWriter::New(std::make_unique<std::ostream>(&keyset));
  if (!writer_result.status().ok()) {
    return "";
  }
  absl::Status status =
      CleartextKeysetHandle::Write((*writer_result).get(), keyset_handle);
  EXPECT_TRUE(status.ok());
  return keyset.str();
}

absl::StatusOr<std::unique_ptr<KeysetHandle>> PrivateKeysetHandle() {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65,
      MlDsaParameters::Variant::kNoPrefixWithPrehashId);
  if (!parameters.status().ok()) return parameters.status();

  return KeysetHandle::GenerateNewFromParameters(
      *parameters, crypto::tink::KeyGenConfigSignature2026());
}

absl::StatusOr<std::unique_ptr<KeysetHandle>> PublicKeysetHandle(
    const KeysetHandle& private_handle) {
  return private_handle.GetPublicKeysetHandle(
      crypto::tink::KeyGenConfigSignature2026());
}

using SignPrehashImplTest = ::testing::Test;

TEST_F(SignPrehashImplTest, CreatePrehashSuccess) {
  SignPrehashImpl service;
  absl::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle =
      PrivateKeysetHandle();
  ASSERT_THAT(private_keyset_handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_keyset_handle =
      PublicKeysetHandle(**private_keyset_handle);
  ASSERT_THAT(public_keyset_handle, IsOk());

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(**public_keyset_handle));
  CreationResponse response;

  EXPECT_TRUE(service.CreatePrehash(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(SignPrehashImplTest, CreatePrehashFailure) {
  SignPrehashImpl service;

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("\x80");
  CreationResponse response;

  EXPECT_TRUE(service.CreatePrehash(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(SignPrehashImplTest, CreatePrehashSignerSuccess) {
  SignPrehashImpl service;
  absl::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle =
      PrivateKeysetHandle();
  ASSERT_THAT(private_keyset_handle, IsOk());

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(**private_keyset_handle));
  CreationResponse response;

  EXPECT_TRUE(service.CreatePrehashSigner(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(SignPrehashImplTest, CreatePrehashSignerFailure) {
  SignPrehashImpl service;

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("\x80");
  CreationResponse response;

  EXPECT_TRUE(service.CreatePrehashSigner(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(SignPrehashImplTest, ComputeAndSignPrehashSuccess) {
  SignPrehashImpl service;
  absl::StatusOr<std::unique_ptr<KeysetHandle>> private_handle =
      PrivateKeysetHandle();
  ASSERT_THAT(private_handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      PublicKeysetHandle(**private_handle);
  ASSERT_THAT(public_handle, IsOk());

  ComputePrehashRequest compute_request;
  compute_request.mutable_public_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(**public_handle));
  compute_request.set_data("some data to prehash");
  ComputePrehashResponse compute_response;

  EXPECT_TRUE(
      service.ComputePrehash(nullptr, &compute_request, &compute_response)
          .ok());
  EXPECT_THAT(compute_response.err(), IsEmpty());
  EXPECT_THAT(compute_response.prehash(), Not(IsEmpty()));

  SignPrehashRequest sign_request;
  sign_request.mutable_private_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(**private_handle));
  sign_request.set_prehash(compute_response.prehash());
  SignPrehashResponse sign_response;

  EXPECT_TRUE(service.SignPrehash(nullptr, &sign_request, &sign_response).ok());
  EXPECT_THAT(sign_response.err(), IsEmpty());
  EXPECT_THAT(sign_response.signature(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
