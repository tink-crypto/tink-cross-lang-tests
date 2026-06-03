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

#include "absl/log/check.h"
#include "tink/aead/internal/config_2026.h"
#include "tink/aead/internal/key_gen_config_2026.h"
#include "tink/aead/internal/kms_aead_config_2026.h"
#include "tink/aead/internal/kms_aead_key_gen_config_2026.h"
#include "tink/aead/x_aes_gcm_proto_serialization.h"
#include "tink/configuration.h"
#include "tink/daead/internal/config_2026.h"
#include "tink/daead/internal/key_gen_config_2026.h"
#include "tink/hybrid/internal/config_2026.h"
#include "tink/hybrid/internal/key_gen_config_2026.h"
#include "tink/jwt/internal/jwt_mac_config_2026.h"
#include "tink/jwt/internal/jwt_mac_key_gen_config_2026.h"
#include "tink/jwt/internal/jwt_signature_config_2026.h"
#include "tink/jwt/internal/jwt_signature_key_gen_config_2026.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyderivation/internal/config_2026.h"
#include "tink/keyderivation/internal/key_gen_config_2026.h"
#include "tink/mac/internal/config_2026.h"
#include "tink/mac/internal/key_gen_config_2026.h"
#include "tink/prf/internal/config_2026.h"
#include "tink/prf/internal/key_gen_config_2026.h"
#include "tink/signature/internal/config_2026.h"
#include "tink/signature/internal/key_gen_config_2026.h"
#include "tink/streamingaead/internal/config_2026.h"
#include "tink/streamingaead/internal/key_gen_config_2026.h"

namespace tink_testing_api {

// The 2026 configuration rules out KMS and JWT, but we need it for the testing
// server. We hence create a testing config by using internal APIs. If as a
// user you need to use such a hack for your use case (i.e merging several
// primitive configurations), please file a bug.
const crypto::tink::Configuration& TestingServerConfig() {
  static const crypto::tink::Configuration* instance = [] {
    auto* config = new crypto::tink::Configuration();
    // We register XAesGcmProtoSerialization to ensure that XAesGcmKey parsing
    // validates output prefix types correctly (only RAW and TINK are
    // supported), preventing inconsistent key creation behavior compared to
    // other languages that use the new serialization format.
    CHECK_OK(crypto::tink::RegisterXAesGcmProtoSerialization());

    CHECK_OK(crypto::tink::internal::AddMac2026(*config));
    CHECK_OK(crypto::tink::internal::AddAead2026(*config));
    CHECK_OK(crypto::tink::internal::AddDeterministicAead2026(*config));
    CHECK_OK(crypto::tink::internal::AddStreamingAead2026(*config));
    CHECK_OK(crypto::tink::internal::AddHybrid2026(*config));
    CHECK_OK(crypto::tink::internal::AddPrf2026(*config));
    CHECK_OK(crypto::tink::internal::AddSignature2026(*config));
    CHECK_OK(crypto::tink::internal::AddKeyDerivation2026(*config));
    CHECK_OK(crypto::tink::internal::AddKmsAead2026(*config));
    CHECK_OK(crypto::tink::jwt_internal::AddJwtMac2026(*config));
    CHECK_OK(crypto::tink::jwt_internal::AddJwtSignature2026(*config));
    return config;
  }();
  return *instance;
}

const crypto::tink::KeyGenConfiguration& TestingServerKeyGenConfig() {
  static const crypto::tink::KeyGenConfiguration* instance = [] {
    auto* config = new crypto::tink::KeyGenConfiguration();
    CHECK_OK(crypto::tink::internal::AddMacKeyGen2026(*config));
    CHECK_OK(crypto::tink::internal::AddAeadKeyGen2026(*config));
    CHECK_OK(crypto::tink::internal::AddDeterministicAeadKeyGen2026(*config));
    CHECK_OK(crypto::tink::internal::AddStreamingAeadKeyGen2026(*config));
    CHECK_OK(crypto::tink::internal::AddHybridKeyGen2026(*config));
    CHECK_OK(crypto::tink::internal::AddPrfKeyGen2026(*config));
    CHECK_OK(crypto::tink::internal::AddSignatureKeyGen2026(*config));
    CHECK_OK(crypto::tink::internal::AddKeyDerivationKeyGen2026(*config));
    CHECK_OK(crypto::tink::internal::AddKmsAeadKeyGen2026(*config));
    CHECK_OK(crypto::tink::jwt_internal::AddJwtMacKeyGen2026(*config));
    CHECK_OK(crypto::tink::jwt_internal::AddJwtSignatureKeyGen2026(*config));
    return config;
  }();
  return *instance;
}

}  // namespace tink_testing_api
