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
#include "absl/base/no_destructor.h"
#include "absl/log/check.h"
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

struct TestKeysets {
  std::string private_keyset;
  std::string public_keyset;
};

const TestKeysets& GetTestKeysets() {
  static const absl::NoDestructor<TestKeysets> keysets([]() {
    absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
        MlDsaParameters::Instance::kMlDsa65,
        MlDsaParameters::Variant::kNoPrefixWithPrehashId);
    CHECK_OK(parameters.status());
    absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        KeysetHandle::GenerateNewFromParameters(
            *parameters, crypto::tink::KeyGenConfigSignature2026());
    CHECK_OK(handle.status());
    absl::StatusOr<std::unique_ptr<KeysetHandle>> pub_handle =
        (*handle)->GetPublicKeysetHandle(
            crypto::tink::KeyGenConfigSignature2026());
    CHECK_OK(pub_handle.status());
    return TestKeysets{KeysetBytes(**handle), KeysetBytes(**pub_handle)};
  }());
  return *keysets;
}

using SignPrehashImplTest = ::testing::Test;

TEST_F(SignPrehashImplTest, CreatePrehashSuccess) {
  SignPrehashImpl service;
  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      GetTestKeysets().public_keyset);
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
  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      GetTestKeysets().private_keyset);
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
  const TestKeysets& test_keysets = GetTestKeysets();

  ComputePrehashRequest compute_request;
  compute_request.mutable_public_annotated_keyset()->set_serialized_keyset(
      test_keysets.public_keyset);
  compute_request.set_data("some data to prehash");
  ComputePrehashResponse compute_response;

  EXPECT_TRUE(
      service.ComputePrehash(nullptr, &compute_request, &compute_response)
          .ok());
  EXPECT_THAT(compute_response.err(), IsEmpty());
  EXPECT_THAT(compute_response.prehash(), Not(IsEmpty()));

  SignPrehashRequest sign_request;
  sign_request.mutable_private_annotated_keyset()->set_serialized_keyset(
      test_keysets.private_keyset);
  sign_request.set_prehash(compute_response.prehash());
  SignPrehashResponse sign_response;

  EXPECT_TRUE(service.SignPrehash(nullptr, &sign_request, &sign_response).ok());
  EXPECT_THAT(sign_response.err(), IsEmpty());
  EXPECT_THAT(sign_response.signature(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
