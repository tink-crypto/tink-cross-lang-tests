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

#include "testing_server_config.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/configuration.h"
#include "tink/deterministic_aead.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/mac.h"
#include "tink/prf/prf_set.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/streaming_aead.h"

namespace tink_testing_api {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::Aead;
using ::crypto::tink::DeterministicAead;
using ::crypto::tink::HybridDecrypt;
using ::crypto::tink::HybridEncrypt;
using ::crypto::tink::JwtMac;
using ::crypto::tink::JwtPublicKeySign;
using ::crypto::tink::JwtPublicKeyVerify;
using ::crypto::tink::KeysetDeriver;
using ::crypto::tink::Mac;
using ::crypto::tink::PrfSet;
using ::crypto::tink::PublicKeySign;
using ::crypto::tink::PublicKeyVerify;
using ::crypto::tink::StreamingAead;
using ::crypto::tink::internal::ConfigurationImpl;
using ::crypto::tink::internal::KeysetWrapperStore;
using ::crypto::tink::internal::KeyTypeInfoStore;

TEST(TestingServerConfigTest, RegistersExpectedWrappers) {
  const crypto::tink::Configuration& config = TestingServerConfig();
  absl::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<Mac>(), IsOk());
  EXPECT_THAT((*store)->Get<Aead>(), IsOk());
  EXPECT_THAT((*store)->Get<DeterministicAead>(), IsOk());
  EXPECT_THAT((*store)->Get<StreamingAead>(), IsOk());
  EXPECT_THAT((*store)->Get<HybridDecrypt>(), IsOk());
  EXPECT_THAT((*store)->Get<HybridEncrypt>(), IsOk());
  EXPECT_THAT((*store)->Get<PrfSet>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeyVerify>(), IsOk());
  EXPECT_THAT((*store)->Get<KeysetDeriver>(), IsOk());
  EXPECT_THAT((*store)->Get<JwtMac>(), IsOk());
  EXPECT_THAT((*store)->Get<JwtPublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<JwtPublicKeyVerify>(), IsOk());
}

TEST(TestingServerConfigTest, RegistersExpectedKeyTypes) {
  const crypto::tink::Configuration& config = TestingServerConfig();
  absl::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  // Verify key types from all recommended standard primitives
  EXPECT_THAT((*store)->Get("type.googleapis.com/google.crypto.tink.HmacKey"),
              IsOk());
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.AesCmacKey"),
      IsOk());
  EXPECT_THAT((*store)->Get("type.googleapis.com/google.crypto.tink.AesGcmKey"),
              IsOk());
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.AesGcmSivKey"),
      IsOk());
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey"),
      IsOk());
  EXPECT_THAT((*store)->Get("type.googleapis.com/google.crypto.tink.AesEaxKey"),
              IsOk());
  EXPECT_THAT(
      (*store)->Get(
          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"),
      IsOk());
  EXPECT_THAT((*store)->Get("type.googleapis.com/google.crypto.tink.AesSivKey"),
              IsOk());
  EXPECT_THAT(
      (*store)->Get(
          "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"),
      IsOk());
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.HpkePrivateKey"),
      IsOk());
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.HpkePublicKey"),
      IsOk());
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.HmacPrfKey"),
      IsOk());
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"),
      IsOk());
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"),
      IsOk());
  EXPECT_THAT(
      (*store)->Get(
          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"),
      IsOk());
  EXPECT_THAT((*store)->Get(
                  "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey"),
              IsOk());
  EXPECT_THAT((*store)->Get(
                  "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"),
              IsOk());

  // Verify KMS AEAD key types
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.KmsAeadKey"),
      IsOk());
  EXPECT_THAT((*store)->Get(
                  "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey"),
              IsOk());

  // Verify JWT AEAD and Signature key types
  EXPECT_THAT(
      (*store)->Get("type.googleapis.com/google.crypto.tink.JwtHmacKey"),
      IsOk());
  EXPECT_THAT((*store)->Get(
                  "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"),
              IsOk());
  EXPECT_THAT(
      (*store)->Get(
          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey"),
      IsOk());
  EXPECT_THAT(
      (*store)->Get(
          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey"),
      IsOk());
}

}  // namespace
}  // namespace tink_testing_api
