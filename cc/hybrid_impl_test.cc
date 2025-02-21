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

#include "hybrid_impl.h"

#include <memory>
#include <ostream>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/hybrid/hybrid_config.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "protos/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::HybridKeyTemplates;

using ::testing::Eq;
using ::testing::IsEmpty;
using ::tink_testing_api::CreationRequest;
using ::tink_testing_api::CreationResponse;
using ::tink_testing_api::HybridDecryptRequest;
using ::tink_testing_api::HybridDecryptResponse;
using ::tink_testing_api::HybridEncryptRequest;
using ::tink_testing_api::HybridEncryptResponse;

using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;

std::string KeysetBytes(const KeysetHandle& keyset_handle) {
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  EXPECT_TRUE(writer_result.ok());
  auto status =
      CleartextKeysetHandle::Write(writer_result.value().get(), keyset_handle);
  EXPECT_TRUE(status.ok());
  return keyset.str();
}

class HybridImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(HybridConfig::Register().ok()); }
};

TEST_F(HybridImplTest, CreateHybridDecryptSuccess) {
  tink_testing_api::HybridImpl hybrid;
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
  absl::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_TRUE(private_keyset_handle.status().ok())
      << private_keyset_handle.status();

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(**private_keyset_handle));
  CreationResponse response;

  EXPECT_TRUE(hybrid.CreateHybridDecrypt(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(HybridImplTest, CreateHybridDecryptFailure) {
  tink_testing_api::HybridImpl hybrid;

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("\x80");
  CreationResponse response;

  EXPECT_TRUE(hybrid.CreateHybridDecrypt(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(HybridImplTest, CreateHybridEncryptSuccess) {
  tink_testing_api::HybridImpl hybrid;
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
  absl::StatusOr<std::unique_ptr<KeysetHandle>> private_keyset_handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_TRUE(private_keyset_handle.status().ok())
      << private_keyset_handle.status();
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_keyset_handle =
      (*private_keyset_handle)
          ->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_TRUE(public_keyset_handle.status().ok())
      << public_keyset_handle.status();

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(**public_keyset_handle));
  CreationResponse response;

  EXPECT_TRUE(hybrid.CreateHybridEncrypt(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(HybridImplTest, CreateHybridEncryptFailure) {
  tink_testing_api::HybridImpl hybrid;

  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("\x80");
  CreationResponse response;

  EXPECT_TRUE(hybrid.CreateHybridEncrypt(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(HybridImplTest, EncryptDecryptSuccess) {
  tink_testing_api::HybridImpl hybrid;
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
  auto private_handle_result =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  EXPECT_TRUE(private_handle_result.ok());
  auto public_handle_result =
      private_handle_result.value()->GetPublicKeysetHandle(
          KeyGenConfigGlobalRegistry());
  EXPECT_TRUE(public_handle_result.ok());

  HybridEncryptRequest enc_request;
  enc_request.mutable_public_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(*public_handle_result.value()));
  enc_request.set_plaintext("Plain text");
  enc_request.set_context_info("context");
  HybridEncryptResponse enc_response;

  EXPECT_TRUE(hybrid.Encrypt(nullptr, &enc_request, &enc_response).ok());
  EXPECT_THAT(enc_response.err(), IsEmpty());

  HybridDecryptRequest dec_request;
  dec_request.mutable_private_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(*private_handle_result.value()));
  dec_request.set_ciphertext(enc_response.ciphertext());
  dec_request.set_context_info("context");
  HybridDecryptResponse dec_response;

  EXPECT_TRUE(hybrid.Decrypt(nullptr, &dec_request, &dec_response).ok());
  EXPECT_THAT(dec_response.err(), IsEmpty());
  EXPECT_THAT(dec_response.plaintext(), Eq("Plain text"));
}

TEST_F(HybridImplTest, EncryptBadKeysetFail) {
  tink_testing_api::HybridImpl hybrid;
  HybridEncryptRequest enc_request;
  enc_request.mutable_public_annotated_keyset()->set_serialized_keyset(
      "bad keyset");
  enc_request.set_plaintext("Plain text");
  enc_request.set_context_info("context");
  HybridEncryptResponse enc_response;

  EXPECT_TRUE(hybrid.Encrypt(nullptr, &enc_request, &enc_response).ok());
  EXPECT_THAT(enc_response.err(), Not(IsEmpty()));
}

TEST_F(HybridImplTest, DecryptBadCiphertextFail) {
  tink_testing_api::HybridImpl hybrid;
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
  auto private_handle_result =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  EXPECT_TRUE(private_handle_result.ok());

  HybridDecryptRequest dec_request;
  dec_request.mutable_private_annotated_keyset()->set_serialized_keyset(
      KeysetBytes(*private_handle_result.value()));
  dec_request.set_ciphertext("bad ciphertext");
  dec_request.set_context_info("context");
  HybridDecryptResponse dec_response;

  EXPECT_TRUE(hybrid.Decrypt(nullptr, &dec_request, &dec_response).ok());
  EXPECT_THAT(dec_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
