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

#include "keyset_impl.h"

#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/config/tink_config.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/util/test_matchers.h"
#include "protos/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::AeadKeyTemplates;
using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::HybridKeyTemplates;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::TestWithParam;
using ::tink_testing_api::KeysetFromJsonRequest;
using ::tink_testing_api::KeysetFromJsonResponse;
using ::tink_testing_api::KeysetGenerateRequest;
using ::tink_testing_api::KeysetGenerateResponse;
using ::tink_testing_api::KeysetPublicRequest;
using ::tink_testing_api::KeysetPublicResponse;
using ::tink_testing_api::KeysetReadEncryptedRequest;
using ::tink_testing_api::KeysetReadEncryptedResponse;
using ::tink_testing_api::KeysetTemplateRequest;
using ::tink_testing_api::KeysetTemplateResponse;
using ::tink_testing_api::KeysetToJsonRequest;
using ::tink_testing_api::KeysetToJsonResponse;
using ::tink_testing_api::KeysetWriteEncryptedRequest;
using ::tink_testing_api::KeysetWriteEncryptedResponse;

class KeysetImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(TinkConfig::Register().ok()); }
};

TEST_F(KeysetImplTest, GenerateSuccess) {
  tink_testing_api::KeysetImpl keyset;
  const KeyTemplate& key_template = AeadKeyTemplates::Aes128Eax();
  KeysetGenerateRequest request;
  std::string templ;
  EXPECT_TRUE(key_template.SerializeToString(&templ));
  request.set_template_(templ);
  KeysetGenerateResponse response;

  EXPECT_TRUE(keyset.Generate(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());

  auto reader_result = BinaryKeysetReader::New(response.keyset());
  ASSERT_TRUE(reader_result.ok());
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  EXPECT_TRUE(handle_result.ok());
}

TEST_F(KeysetImplTest, GenerateFail) {
  tink_testing_api::KeysetImpl keyset;

  KeysetGenerateRequest request;
  request.set_template_("bad template");
  KeysetGenerateResponse response;
  EXPECT_TRUE(keyset.Generate(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

util::StatusOr<std::string> AeadKeyset() {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry());
  if (!handle.ok()) {
    return handle.status();
  }
  std::stringbuf keyset;
  util::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!handle.ok()) {
    return handle.status();
  }
  util::Status status = CleartextKeysetHandle::Write(writer->get(), **handle);
  if (!status.ok()) {
    return status;
  }
  return keyset.str();
}

util::StatusOr<std::string> ValidPrivateKeyset() {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(
          HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm(),
          KeyGenConfigGlobalRegistry());
  if (!handle.ok()) {
    return handle.status();
  }
  std::stringbuf keyset;
  util::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!writer.ok()) {
    return writer.status();
  }
  util::Status status = CleartextKeysetHandle::Write(writer->get(), **handle);
  if (!status.ok()) {
    return status;
  }
  return keyset.str();
}

TEST_F(KeysetImplTest, PublicSuccess) {
  tink_testing_api::KeysetImpl keyset;

  util::StatusOr<std::string> private_keyset = ValidPrivateKeyset();
  ASSERT_THAT(private_keyset.status(), IsOk());

  KeysetPublicRequest request;
  request.set_private_keyset(*private_keyset);
  KeysetPublicResponse response;

  EXPECT_TRUE(keyset.Public(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());

  auto reader_result = BinaryKeysetReader::New(response.public_keyset());
  ASSERT_TRUE(reader_result.ok());
  auto public_handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  EXPECT_TRUE(public_handle_result.ok());
}

TEST_F(KeysetImplTest, PublicFail) {
  tink_testing_api::KeysetImpl keyset;

  KeysetPublicRequest request;
  request.set_private_keyset("bad keyset");
  KeysetPublicResponse response;
  EXPECT_TRUE(keyset.Public(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(KeysetImplTest, FromJsonSuccess) {
  tink_testing_api::KeysetImpl keyset;
  std::string json_keyset = R""""(
        {
          "primaryKeyId": 42,
          "key": [
            {
              "keyData": {
                "typeUrl": "type.googleapis.com/google.crypto.tink.FakeKeyType",
                "keyMaterialType": "SYMMETRIC",
                "value": "AFakeTestKeyValue1234567"
              },
              "outputPrefixType": "TINK",
              "keyId": 42,
              "status": "ENABLED"
            }
          ]
        })"""";
  KeysetFromJsonRequest from_request;
  from_request.set_json_keyset(json_keyset);
  KeysetFromJsonResponse from_response;
  EXPECT_TRUE(keyset.FromJson(nullptr, &from_request, &from_response).ok());
  EXPECT_THAT(from_response.err(), IsEmpty());
  std::string output = from_response.keyset();

  auto reader_result = BinaryKeysetReader::New(from_response.keyset());
  EXPECT_TRUE(reader_result.ok());
  auto keyset_proto_result = reader_result.value()->Read();
  EXPECT_TRUE(keyset_proto_result.ok());
  EXPECT_THAT(keyset_proto_result.value()->primary_key_id(), Eq(42));
}

TEST_F(KeysetImplTest, ToFromJsonSuccess) {
  tink_testing_api::KeysetImpl keyset;
  util::StatusOr<std::string> private_keyset = ValidPrivateKeyset();
  EXPECT_THAT(private_keyset.status(), IsOk());

  KeysetToJsonRequest to_request;
  to_request.set_keyset(*private_keyset);
  KeysetToJsonResponse to_response;
  EXPECT_TRUE(keyset.ToJson(nullptr, &to_request, &to_response).ok());
  EXPECT_THAT(to_response.err(), IsEmpty());
  std::string json_keyset = to_response.json_keyset();

  KeysetFromJsonRequest from_request;
  from_request.set_json_keyset(json_keyset);
  KeysetFromJsonResponse from_response;
  EXPECT_TRUE(keyset.FromJson(nullptr, &from_request, &from_response).ok());
  EXPECT_THAT(from_response.err(), IsEmpty());
  std::string output = from_response.keyset();
  EXPECT_THAT(from_response.keyset(), Eq(*private_keyset));
}

TEST_F(KeysetImplTest, ToJsonFail) {
  tink_testing_api::KeysetImpl keyset;

  KeysetToJsonRequest request;
  request.set_keyset("bad keyset");
  KeysetToJsonResponse response;
  EXPECT_TRUE(keyset.ToJson(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(KeysetImplTest, FromJsonFail) {
  tink_testing_api::KeysetImpl keyset;

  KeysetFromJsonRequest request;
  request.set_json_keyset("bad json keyset");
  KeysetFromJsonResponse response;
  EXPECT_TRUE(keyset.FromJson(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(KeysetImplTest, ReadWriteEncryptedKeysetSuccess) {
  tink_testing_api::KeysetImpl keyset_impl;

  util::StatusOr<std::string> master_keyset = AeadKeyset();
  ASSERT_THAT(master_keyset.status(), IsOk());
  util::StatusOr<std::string> keyset = AeadKeyset();
  ASSERT_THAT(master_keyset.status(), IsOk());

  KeysetWriteEncryptedRequest write_request;
  write_request.set_keyset(*keyset);
  write_request.set_master_keyset(*master_keyset);
  write_request.set_keyset_writer_type(tink_testing_api::KEYSET_WRITER_BINARY);
  KeysetWriteEncryptedResponse write_response;

  ASSERT_TRUE(
      keyset_impl
          .WriteEncrypted(/*context=*/nullptr, &write_request, &write_response)
          .ok());
  ASSERT_THAT(write_response.err(), IsEmpty());

  KeysetReadEncryptedRequest read_request;
  read_request.set_encrypted_keyset(write_response.encrypted_keyset());
  read_request.set_master_keyset(*master_keyset);
  read_request.set_keyset_reader_type(tink_testing_api::KEYSET_READER_BINARY);
  KeysetReadEncryptedResponse read_response;

  ASSERT_TRUE(
      keyset_impl
          .ReadEncrypted(/*context=*/nullptr, &read_request, &read_response)
          .ok());
  EXPECT_THAT(read_response.err(), IsEmpty());
  EXPECT_EQ(read_response.keyset(), *keyset);
}

TEST_F(KeysetImplTest, ReadWriteEncryptedWithAssociatedDataKeysetSuccess) {
  tink_testing_api::KeysetImpl keyset_impl;

  util::StatusOr<std::string> master_keyset = AeadKeyset();
  ASSERT_THAT(master_keyset.status(), IsOk());
  util::StatusOr<std::string> keyset = AeadKeyset();
  ASSERT_THAT(keyset.status(), IsOk());
  std::string associated_data = "associated_data";

  KeysetWriteEncryptedRequest write_request;
  write_request.set_keyset(*keyset);
  write_request.set_master_keyset(*master_keyset);
  write_request.mutable_associated_data()->set_value(associated_data);
  write_request.set_keyset_writer_type(tink_testing_api::KEYSET_WRITER_BINARY);
  KeysetWriteEncryptedResponse write_response;

  ASSERT_TRUE(
      keyset_impl
          .WriteEncrypted(/*context=*/nullptr, &write_request, &write_response)
          .ok());
  ASSERT_THAT(write_response.err(), IsEmpty());

  KeysetReadEncryptedRequest read_request;
  read_request.set_encrypted_keyset(write_response.encrypted_keyset());
  read_request.set_master_keyset(*master_keyset);
  read_request.mutable_associated_data()->set_value(associated_data);
  read_request.set_keyset_reader_type(tink_testing_api::KEYSET_READER_BINARY);
  KeysetReadEncryptedResponse read_response;

  ASSERT_TRUE(
      keyset_impl
          .ReadEncrypted(/*context=*/nullptr, &read_request, &read_response)
          .ok());
  EXPECT_THAT(read_response.err(), IsEmpty());
  EXPECT_EQ(read_response.keyset(), *keyset);
}

TEST_F(KeysetImplTest, WriteEncryptedKeysetFail) {
  tink_testing_api::KeysetImpl keyset_impl;

  util::StatusOr<std::string> master_keyset = AeadKeyset();
  ASSERT_THAT(master_keyset.status(), IsOk());

  KeysetWriteEncryptedRequest write_request;
  write_request.set_keyset("invalid");
  write_request.set_master_keyset(*master_keyset);
  write_request.set_keyset_writer_type(tink_testing_api::KEYSET_WRITER_BINARY);
  KeysetWriteEncryptedResponse write_response;

  ASSERT_TRUE(
      keyset_impl
          .WriteEncrypted(/*context=*/nullptr, &write_request, &write_response)
          .ok());
  EXPECT_THAT(write_response.err(), Not(IsEmpty()));
}

TEST_F(KeysetImplTest, ReadEncryptedKeysetFail) {
  tink_testing_api::KeysetImpl keyset_impl;

  util::StatusOr<std::string> master_keyset = AeadKeyset();
  ASSERT_THAT(master_keyset.status(), IsOk());

  KeysetReadEncryptedRequest read_request;
  read_request.set_encrypted_keyset("invalid");
  read_request.set_master_keyset(*master_keyset);
  read_request.set_keyset_reader_type(tink_testing_api::KEYSET_READER_BINARY);
  KeysetReadEncryptedResponse read_response;

  ASSERT_TRUE(
      keyset_impl
          .ReadEncrypted(/*context=*/nullptr, &read_request, &read_response)
          .ok());
  EXPECT_THAT(read_response.err(), Not(IsEmpty()));
}

using GetTemplateTest = TestWithParam<std::string>;

TEST_P(GetTemplateTest, GetTemplateSuccess) {
  tink_testing_api::KeysetImpl keyset_impl;

  KeysetTemplateRequest request;
  request.set_template_name(GetParam());
  KeysetTemplateResponse response;

  ASSERT_TRUE(
      keyset_impl.GetTemplate(/*context=*/nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
  EXPECT_THAT(response.key_template(), Not(IsEmpty()));
}

INSTANTIATE_TEST_SUITE_P(
    GetTemplateTests, GetTemplateTest,
    ::testing::ValuesIn(std::vector<std::string>{
        "AES128_EAX",
        "AES256_EAX",
        "AES128_GCM",
        "AES128_GCM_RAW",
        "AES256_GCM",
        "AES256_GCM_RAW",
        "AES128_GCM_SIV",
        "AES256_GCM_SIV",
        "AES128_CTR_HMAC_SHA256",
        "AES256_CTR_HMAC_SHA256",
        "CHACHA20_POLY1305",
        "XCHACHA20_POLY1305",
        "AES256_SIV",
        "X_AES_GCM_8_BYTE_SALT_NO_PREFIX",
        "AES128_CTR_HMAC_SHA256_4KB",
        "AES128_CTR_HMAC_SHA256_1MB",
        "AES256_CTR_HMAC_SHA256_4KB",
        "AES256_CTR_HMAC_SHA256_1MB",
        "AES128_GCM_HKDF_4KB",
        "AES256_GCM_HKDF_4KB",
        "AES256_GCM_HKDF_1MB",
        "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
        "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM",
        "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
        "ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305",
        "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW",
        "AES_CMAC",
        "HMAC_SHA256_128BITTAG",
        "HMAC_SHA256_256BITTAG",
        "HMAC_SHA512_256BITTAG",
        "HMAC_SHA512_512BITTAG",
        "ECDSA_P256",
        "ECDSA_P256_RAW",
        "ECDSA_P384",
        "ECDSA_P384_SHA384",
        "ECDSA_P384_SHA512",
        "ECDSA_P521",
        "ECDSA_P256_IEEE_P1363",
        "ECDSA_P384_IEEE_P1363",
        "ECDSA_P521_IEEE_P1363",
        "ED25519",
        "RSA_SSA_PKCS1_3072_SHA256_F4",
        "RSA_SSA_PKCS1_4096_SHA512_F4",
        "RSA_SSA_PSS_3072_SHA256_SHA256_32_F4",
        "RSA_SSA_PSS_4096_SHA512_SHA512_64_F4",
        "AES_CMAC_PRF",
        "HMAC_SHA256_PRF",
        "HMAC_SHA512_PRF",
        "HKDF_SHA256",
        "JWT_HS256",
        "JWT_HS256_RAW",
        "JWT_HS384",
        "JWT_HS384_RAW",
        "JWT_HS512",
        "JWT_HS512_RAW",
        "JWT_ES256",
        "JWT_ES256_RAW",
        "JWT_ES384",
        "JWT_ES384_RAW",
        "JWT_ES512",
        "JWT_ES512_RAW",
        "JWT_RS256_2048_F4",
        "JWT_RS256_2048_F4_RAW",
        "JWT_RS256_3072_F4",
        "JWT_RS256_3072_F4_RAW",
        "JWT_RS384_3072_F4",
        "JWT_RS384_3072_F4_RAW",
        "JWT_RS512_4096_F4",
        "JWT_RS512_4096_F4_RAW",
        "JWT_PS256_2048_F4",
        "JWT_PS256_2048_F4_RAW",
        "JWT_PS256_3072_F4",
        "JWT_PS256_3072_F4_RAW",
        "JWT_PS384_3072_F4",
        "JWT_PS384_3072_F4_RAW",
        "JWT_PS512_4096_F4",
        "JWT_PS512_4096_F4_RAW"}));

}  // namespace
}  // namespace tink
}  // namespace crypto
