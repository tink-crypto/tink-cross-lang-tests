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

#include "signature_impl.h"

#include <memory>
#include <ostream>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "tink/signature/key_gen_config_2026.h"
#include "tink/signature/signature_key_templates.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::SignatureKeyTemplates;

using ::testing::IsEmpty;
using ::tink_testing_api::CreationRequest;
using ::tink_testing_api::CreationResponse;
using ::tink_testing_api::SignatureSignRequest;
using ::tink_testing_api::SignatureSignResponse;
using ::tink_testing_api::SignatureVerifyRequest;
using ::tink_testing_api::SignatureVerifyResponse;

using crypto::tink::KeysetHandle;

std::string KeysetBytes(const KeysetHandle& keyset_handle) {
  std::stringbuf keyset;
  absl::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer_result =
      BinaryKeysetWriter::New(std::make_unique<std::ostream>(&keyset));
  EXPECT_TRUE(writer_result.ok());
  absl::Status status =
      CleartextKeysetHandle::Write(writer_result.value().get(), keyset_handle);
  EXPECT_TRUE(status.ok());
  return keyset.str();
}

struct TestKeysets {
  std::string private_keyset;
  std::string public_keyset;
};

const TestKeysets& GetTestKeysets() {
  static const absl::NoDestructor<TestKeysets> keysets([]() {
    absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        KeysetHandle::GenerateNew(SignatureKeyTemplates::EcdsaP256(),
                                  crypto::tink::KeyGenConfigSignature2026());
    CHECK_OK(handle);
    absl::StatusOr<std::unique_ptr<KeysetHandle>> pub_handle =
        (*handle)->GetPublicKeysetHandle(
            crypto::tink::KeyGenConfigSignature2026());
    CHECK_OK(pub_handle);
    return TestKeysets{KeysetBytes(**handle), KeysetBytes(**pub_handle)};
  }());
  return *keysets;
}

using SignatureImplTest = ::testing::Test;

TEST_F(SignatureImplTest, CreatePublicKeySignSuccess) {
  tink_testing_api::SignatureImpl signature;
  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      GetTestKeysets().private_keyset);
  CreationResponse response;

  EXPECT_TRUE(signature.CreatePublicKeySign(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(SignatureImplTest, CreatePublicKeySignFailure) {
  tink_testing_api::SignatureImpl signature;

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("\x80");
  CreationResponse response;

  EXPECT_TRUE(signature.CreatePublicKeySign(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(SignatureImplTest, CreatePublicKeyVerifySuccess) {
  tink_testing_api::SignatureImpl signature;
  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      GetTestKeysets().public_keyset);
  CreationResponse response;

  EXPECT_TRUE(
      signature.CreatePublicKeyVerify(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(SignatureImplTest, CreatePublicKeyVerifyFailure) {
  tink_testing_api::SignatureImpl signature;

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("\x80");
  CreationResponse response;

  EXPECT_TRUE(
      signature.CreatePublicKeyVerify(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(SignatureImplTest, SignVerifySuccess) {
  tink_testing_api::SignatureImpl signature;
  const TestKeysets& test_keysets = GetTestKeysets();

  SignatureSignRequest sign_request;
  sign_request.mutable_private_annotated_keyset()->set_serialized_keyset(
      test_keysets.private_keyset);
  sign_request.set_data("some data");
  SignatureSignResponse sign_response;

  EXPECT_TRUE(signature.Sign(nullptr, &sign_request, &sign_response).ok());
  EXPECT_THAT(sign_response.err(), IsEmpty());

  SignatureVerifyRequest verify_request;
  verify_request.mutable_public_annotated_keyset()->set_serialized_keyset(
      test_keysets.public_keyset);
  verify_request.set_signature(sign_response.signature());
  verify_request.set_data("some data");
  SignatureVerifyResponse verify_response;

  EXPECT_TRUE(
      signature.Verify(nullptr, &verify_request, &verify_response).ok());
  EXPECT_THAT(verify_response.err(), IsEmpty());
}

TEST_F(SignatureImplTest, SignBadKeysetFail) {
  tink_testing_api::SignatureImpl signature;
  SignatureSignRequest sign_request;
  sign_request.mutable_private_annotated_keyset()->set_serialized_keyset(
      "bad private keyset");
  sign_request.set_data("some data");
  SignatureSignResponse sign_response;

  EXPECT_TRUE(signature.Sign(nullptr, &sign_request, &sign_response).ok());
  EXPECT_THAT(sign_response.err(), Not(IsEmpty()));
}

TEST_F(SignatureImplTest, VerifyBadCiphertextFail) {
  tink_testing_api::SignatureImpl signature;
  const TestKeysets& test_keysets = GetTestKeysets();

  SignatureVerifyRequest verify_request;
  verify_request.mutable_public_annotated_keyset()->set_serialized_keyset(
      test_keysets.public_keyset);
  verify_request.set_signature("bad signature");
  verify_request.set_data("some data");
  SignatureVerifyResponse verify_response;

  EXPECT_TRUE(
      signature.Verify(nullptr, &verify_request, &verify_response).ok());
  EXPECT_THAT(verify_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
