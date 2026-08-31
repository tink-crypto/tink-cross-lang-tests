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

#include "streaming_aead_impl.h"

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
#include "tink/streamingaead/key_gen_config_2026.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::StreamingAeadKeyTemplates;

using ::testing::Eq;
using ::testing::IsEmpty;
using ::tink_testing_api::CreationRequest;
using ::tink_testing_api::CreationResponse;
using ::tink_testing_api::StreamingAeadDecryptRequest;
using ::tink_testing_api::StreamingAeadDecryptResponse;
using ::tink_testing_api::StreamingAeadEncryptRequest;
using ::tink_testing_api::StreamingAeadEncryptResponse;

using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;

const std::string& ValidKeyset() {
  static const absl::NoDestructor<std::string> keyset([]() {
    const KeyTemplate& key_template =
        StreamingAeadKeyTemplates::Aes128GcmHkdf4KB();
    absl::StatusOr<std::unique_ptr<KeysetHandle>> handle_result =
        KeysetHandle::GenerateNew(
            key_template, crypto::tink::KeyGenConfigStreamingAead2026());
    CHECK_OK(handle_result.status());
    std::stringbuf keyset_buf;
    absl::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer_result =
        BinaryKeysetWriter::New(std::make_unique<std::ostream>(&keyset_buf));
    CHECK_OK(writer_result.status());

    absl::Status status = CleartextKeysetHandle::Write(
        writer_result.value().get(), *handle_result.value());
    CHECK_OK(status);
    return keyset_buf.str();
  }());
  return *keyset;
}

class StreamingAeadImplTest : public ::testing::Test {};

TEST_F(StreamingAeadImplTest, CreateSuccess) {
  tink_testing_api::StreamingAeadImpl streaming_aead;
  std::string keyset = ValidKeyset();
  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(keyset);
  CreationResponse response;

  EXPECT_TRUE(streaming_aead.Create(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(StreamingAeadImplTest, CreateFails) {
  tink_testing_api::StreamingAeadImpl streaming_aead;
  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("bad keyset");
  CreationResponse response;

  EXPECT_TRUE(streaming_aead.Create(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}


TEST_F(StreamingAeadImplTest, EncryptDecryptSuccess) {
  tink_testing_api::StreamingAeadImpl streaming_aead;
  std::string keyset = ValidKeyset();
  StreamingAeadEncryptRequest enc_request;
  enc_request.mutable_annotated_keyset()->set_serialized_keyset(keyset);
  enc_request.set_plaintext("Plain text");
  enc_request.set_associated_data("ad");
  StreamingAeadEncryptResponse enc_response;

  EXPECT_TRUE(streaming_aead.Encrypt(nullptr, &enc_request,
                                     &enc_response).ok());
  EXPECT_THAT(enc_response.err(), IsEmpty());

  StreamingAeadDecryptRequest dec_request;
  dec_request.mutable_annotated_keyset()->set_serialized_keyset(keyset);
  dec_request.set_ciphertext(enc_response.ciphertext());
  dec_request.set_associated_data("ad");
  StreamingAeadDecryptResponse dec_response;

  EXPECT_TRUE(streaming_aead.Decrypt(nullptr, &dec_request,
                                     &dec_response).ok());
  EXPECT_THAT(dec_response.err(), IsEmpty());
  EXPECT_THAT(dec_response.plaintext(), Eq("Plain text"));
}

TEST_F(StreamingAeadImplTest, EncryptBadKeysetFail) {
  tink_testing_api::StreamingAeadImpl streaming_aead;
  StreamingAeadEncryptRequest enc_request;
  enc_request.mutable_annotated_keyset()->set_serialized_keyset("bad keyset");
  enc_request.set_plaintext("Plain text");
  enc_request.set_associated_data("ad");
  StreamingAeadEncryptResponse enc_response;

  EXPECT_TRUE(streaming_aead.Encrypt(nullptr, &enc_request,
                                     &enc_response).ok());
  EXPECT_THAT(enc_response.err(), Not(IsEmpty()));
}

TEST_F(StreamingAeadImplTest, DecryptBadCiphertextFail) {
  tink_testing_api::StreamingAeadImpl streaming_aead;
  std::string keyset = ValidKeyset();
  StreamingAeadDecryptRequest dec_request;
  dec_request.mutable_annotated_keyset()->set_serialized_keyset(keyset);
  dec_request.set_ciphertext("bad ciphertext");
  dec_request.set_associated_data("ad");
  StreamingAeadDecryptResponse dec_response;

  EXPECT_TRUE(streaming_aead.Decrypt(nullptr, &dec_request,
                                     &dec_response).ok());
  EXPECT_THAT(dec_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
