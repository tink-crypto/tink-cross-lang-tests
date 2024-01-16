// Copyright 2021 Google LLC
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

#include "keyset_deriver_impl.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/config/tink_config.h"
#include "tink/keyderivation/key_derivation_config.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::testing::IsEmpty;
using ::tink_testing_api::CreationRequest;
using ::tink_testing_api::CreationResponse;
using ::tink_testing_api::DeriveKeysetRequest;
using ::tink_testing_api::DeriveKeysetResponse;

class KeysetDeriverImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    ASSERT_THAT(::crypto::tink::TinkConfig::Register(), IsOk());
    ASSERT_THAT(::crypto::tink::KeyDerivationConfig::Register(), IsOk());
  }
};

TEST_F(KeysetDeriverImplTest, CreateSuccess) {
  KeyData key_data;
  key_data.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  key_data.set_value(
      "\022]\n1type.googleapis.com/"
      "google.crypto.tink.HkdfPrfKey\022&\022\002\010\003\032 "
      "\031\356\303i(\211\366\254U\312\212\362x3\"fs\261c\021+\322D(]\336\316>"
      "\200\360V\020\030\001\032:\n8\n0type.googleapis.com/"
      "google.crypto.tink.AesGcmKey\022\002\020 \030\001");
  key_data.set_key_material_type(KeyData::SYMMETRIC);
  Keyset keyset;
  keyset.set_primary_key_id(497208648);
  Keyset::Key& key = *keyset.add_key();
  *key.mutable_key_data() = key_data;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(497208648);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);

  std::string serialized_keyset = keyset.SerializeAsString();
  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(serialized_keyset);
  CreationResponse response;

  tink_testing_api::KeysetDeriverImpl keyset_deriver;
  EXPECT_TRUE(keyset_deriver.Create(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(KeysetDeriverImplTest, CreateFails) {
  tink_testing_api::KeysetDeriverImpl keyset_deriver;
  CreationRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("bad keyset");
  CreationResponse response;

  EXPECT_TRUE(keyset_deriver.Create(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(KeysetDeriverImplTest, DeriveKeysetSuccess) {
  KeyData key_data;
  key_data.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  key_data.set_value(
      "\022]\n1type.googleapis.com/"
      "google.crypto.tink.HkdfPrfKey\022&\022\002\010\003\032 "
      "\031\356\303i(\211\366\254U\312\212\362x3\"fs\261c\021+\322D(]\336\316>"
      "\200\360V\020\030\001\032:\n8\n0type.googleapis.com/"
      "google.crypto.tink.AesGcmKey\022\002\020 \030\001");
  key_data.set_key_material_type(KeyData::SYMMETRIC);
  Keyset keyset;
  keyset.set_primary_key_id(497208648);
  Keyset::Key& key = *keyset.add_key();
  *key.mutable_key_data() = key_data;
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key.set_key_id(497208648);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);

  DeriveKeysetRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset(
      keyset.SerializeAsString());
  DeriveKeysetResponse response;

  tink_testing_api::KeysetDeriverImpl keyset_deriver;
  EXPECT_TRUE(
      keyset_deriver.DeriveKeyset(/*context=*/nullptr, &request, &response)
          .ok());
  EXPECT_THAT(response.err(), IsEmpty());

  Keyset derived_keyset;
  derived_keyset.ParseFromString(response.derived_keyset());
  EXPECT_EQ(derived_keyset.key(0).key_data().type_url(),
            "type.googleapis.com/google.crypto.tink.AesGcmKey");
}

TEST_F(KeysetDeriverImplTest, DeriveKeysetFailsOnBadInput) {
  DeriveKeysetRequest request;
  request.mutable_annotated_keyset()->set_serialized_keyset("invalid");
  DeriveKeysetResponse response;

  tink_testing_api::KeysetDeriverImpl keyset_deriver;
  EXPECT_TRUE(
      keyset_deriver.DeriveKeyset(/*context=*/nullptr, &request, &response)
          .ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
