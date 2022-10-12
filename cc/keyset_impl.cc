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

// Implementation of a Keyset Service.
#include "keyset_impl.h"

#include <ostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "tink/aead/aead_key_templates.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/json_keyset_reader.h"
#include "tink/json_keyset_writer.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/keyset_handle.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"
#include "proto/tink.pb.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::JsonKeysetReader;
using ::crypto::tink::JsonKeysetWriter;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::KeysetReader;
using ::crypto::tink::KeysetWriter;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KeyTemplate;

KeysetImpl::KeysetImpl() {
  key_templates_["AES128_EAX"] = crypto::tink::AeadKeyTemplates::Aes128Eax();
  key_templates_["AES256_EAX"] = crypto::tink::AeadKeyTemplates::Aes256Eax();
  key_templates_["AES128_GCM"] = crypto::tink::AeadKeyTemplates::Aes128Gcm();
  key_templates_["AES128_GCM_RAW"] =
      crypto::tink::AeadKeyTemplates::Aes128GcmNoPrefix();
  key_templates_["AES256_GCM"] = crypto::tink::AeadKeyTemplates::Aes256Gcm();
  key_templates_["AES256_GCM_RAW"] =
      crypto::tink::AeadKeyTemplates::Aes256GcmNoPrefix();
  key_templates_["AES128_GCM_SIV"] =
      crypto::tink::AeadKeyTemplates::Aes128GcmSiv();
  key_templates_["AES256_GCM_SIV"] =
      crypto::tink::AeadKeyTemplates::Aes256GcmSiv();
  key_templates_["AES128_CTR_HMAC_SHA256"] =
      crypto::tink::AeadKeyTemplates::Aes128CtrHmacSha256();
  key_templates_["AES256_CTR_HMAC_SHA256"] =
      crypto::tink::AeadKeyTemplates::Aes256CtrHmacSha256();
  key_templates_["CHACHA20_POLY1305"] =
      crypto::tink::AeadKeyTemplates::XChaCha20Poly1305();
  key_templates_["XCHACHA20_POLY1305"] =
      crypto::tink::AeadKeyTemplates::XChaCha20Poly1305();
  key_templates_["AES256_SIV"] =
      crypto::tink::DeterministicAeadKeyTemplates::Aes256Siv();
  key_templates_["AES128_CTR_HMAC_SHA256_4KB"] =
      crypto::tink::StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB();
  key_templates_["AES256_CTR_HMAC_SHA256_4KB"] =
      crypto::tink::StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB();
  key_templates_["AES128_GCM_HKDF_4KB"] =
      crypto::tink::StreamingAeadKeyTemplates::Aes128GcmHkdf4KB();
  key_templates_["AES256_GCM_HKDF_4KB"] =
      crypto::tink::StreamingAeadKeyTemplates::Aes256GcmHkdf4KB();
  key_templates_["AES256_GCM_HKDF_1MB"] =
      crypto::tink::StreamingAeadKeyTemplates::Aes256GcmHkdf1MB();
  key_templates_["ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"] =
      crypto::tink::HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
  key_templates_["ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM"] = crypto::
      tink::HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128Gcm();
  key_templates_["ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256"] =
      crypto::tink::HybridKeyTemplates::
          EciesP256HkdfHmacSha256Aes128CtrHmacSha256();
  key_templates_
      ["ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256"] =
          crypto::tink::HybridKeyTemplates::
              EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256();
  key_templates_["DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM"] =
      crypto::tink::HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm();
  key_templates_["DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW"] =
      crypto::tink::HybridKeyTemplates::HpkeX25519HkdfSha256Aes128GcmRaw();
  key_templates_["DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM"] =
      crypto::tink::HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm();
  key_templates_["DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW"] =
      crypto::tink::HybridKeyTemplates::HpkeX25519HkdfSha256Aes256GcmRaw();
  key_templates_["DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305"] =
      crypto::tink::HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305();
  key_templates_["DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW"] =
      crypto::tink::HybridKeyTemplates::
          HpkeX25519HkdfSha256ChaCha20Poly1305Raw();
  key_templates_["AES_CMAC"] = crypto::tink::MacKeyTemplates::AesCmac();
  key_templates_["HMAC_SHA256_128BITTAG"] =
      crypto::tink::MacKeyTemplates::HmacSha256HalfSizeTag();
  key_templates_["HMAC_SHA256_256BITTAG"] =
      crypto::tink::MacKeyTemplates::HmacSha256();
  key_templates_["HMAC_SHA512_256BITTAG"] =
      crypto::tink::MacKeyTemplates::HmacSha512HalfSizeTag();
  key_templates_["HMAC_SHA512_512BITTAG"] =
      crypto::tink::MacKeyTemplates::HmacSha512();
  key_templates_["ECDSA_P256"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP256();
  key_templates_["ECDSA_P256_RAW"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP256Raw();
  key_templates_["ECDSA_P384"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP384();
  key_templates_["ECDSA_P384_SHA384"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP384Sha384();
  key_templates_["ECDSA_P384_SHA512"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP384Sha512();
  key_templates_["ECDSA_P521"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP521();
  key_templates_["ECDSA_P256_IEEE_P1363"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP256Ieee();
  key_templates_["ECDSA_P384_IEEE_P1363"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP384Ieee();
  key_templates_["ECDSA_P521_IEEE_P1363"] =
      crypto::tink::SignatureKeyTemplates::EcdsaP521Ieee();
  key_templates_["ED25519"] = crypto::tink::SignatureKeyTemplates::Ed25519();
  key_templates_["RSA_SSA_PKCS1_3072_SHA256_F4"] =
      crypto::tink::SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4();
  key_templates_["RSA_SSA_PKCS1_4096_SHA512_F4"] =
      crypto::tink::SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4();
  key_templates_["RSA_SSA_PSS_3072_SHA256_SHA256_32_F4"] =
      crypto::tink::SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4();
  key_templates_["RSA_SSA_PSS_4096_SHA512_SHA512_64_F4"] =
      crypto::tink::SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4();
  key_templates_["AES_CMAC_PRF"] = crypto::tink::PrfKeyTemplates::AesCmac();
  key_templates_["HMAC_SHA256_PRF"] =
      crypto::tink::PrfKeyTemplates::HmacSha256();
  key_templates_["HMAC_SHA512_PRF"] =
      crypto::tink::PrfKeyTemplates::HmacSha512();
  key_templates_["HKDF_SHA256"] = crypto::tink::PrfKeyTemplates::HkdfSha256();
  key_templates_["JWT_HS256"] = crypto::tink::JwtHs256Template();
  key_templates_["JWT_HS256_RAW"] = crypto::tink::RawJwtHs256Template();
  key_templates_["JWT_HS384"] = crypto::tink::JwtHs384Template();
  key_templates_["JWT_HS384_RAW"] = crypto::tink::RawJwtHs384Template();
  key_templates_["JWT_HS512"] = crypto::tink::JwtHs512Template();
  key_templates_["JWT_HS512_RAW"] = crypto::tink::RawJwtHs512Template();
  key_templates_["JWT_ES256"] = crypto::tink::JwtEs256Template();
  key_templates_["JWT_ES256_RAW"] = crypto::tink::RawJwtEs256Template();
  key_templates_["JWT_ES384"] = crypto::tink::JwtEs384Template();
  key_templates_["JWT_ES384_RAW"] = crypto::tink::RawJwtEs384Template();
  key_templates_["JWT_ES512"] = crypto::tink::JwtEs512Template();
  key_templates_["JWT_ES512_RAW"] = crypto::tink::RawJwtEs512Template();
  key_templates_["JWT_RS256_2048_F4"] =
      crypto::tink::JwtRs256_2048_F4_Template();
  key_templates_["JWT_RS256_2048_F4_RAW"] =
      crypto::tink::RawJwtRs256_2048_F4_Template();
  key_templates_["JWT_RS256_3072_F4"] =
      crypto::tink::JwtRs256_3072_F4_Template();
  key_templates_["JWT_RS256_3072_F4_RAW"] =
      crypto::tink::RawJwtRs256_3072_F4_Template();
  key_templates_["JWT_RS384_3072_F4"] =
      crypto::tink::JwtRs384_3072_F4_Template();
  key_templates_["JWT_RS384_3072_F4_RAW"] =
      crypto::tink::RawJwtRs384_3072_F4_Template();
  key_templates_["JWT_RS512_4096_F4"] =
      crypto::tink::JwtRs512_4096_F4_Template();
  key_templates_["JWT_RS512_4096_F4_RAW"] =
      crypto::tink::RawJwtRs512_4096_F4_Template();
  key_templates_["JWT_PS256_2048_F4"] =
      crypto::tink::JwtPs256_2048_F4_Template();
  key_templates_["JWT_PS256_2048_F4_RAW"] =
      crypto::tink::RawJwtPs256_2048_F4_Template();
  key_templates_["JWT_PS256_3072_F4"] =
      crypto::tink::JwtPs256_3072_F4_Template();
  key_templates_["JWT_PS256_3072_F4_RAW"] =
      crypto::tink::RawJwtPs256_3072_F4_Template();
  key_templates_["JWT_PS384_3072_F4"] =
      crypto::tink::JwtPs384_3072_F4_Template();
  key_templates_["JWT_PS384_3072_F4_RAW"] =
      crypto::tink::RawJwtPs384_3072_F4_Template();
  key_templates_["JWT_PS512_4096_F4"] =
      crypto::tink::JwtPs512_4096_F4_Template();
  key_templates_["JWT_PS512_4096_F4_RAW"] =
      crypto::tink::RawJwtPs512_4096_F4_Template();
}

// Returns the key template for the given template name.
grpc::Status KeysetImpl::GetTemplate(grpc::ServerContext* context,
                                       const KeysetTemplateRequest* request,
                                       KeysetTemplateResponse* response) {
  auto it = key_templates_.find(request->template_name());
  if (it == key_templates_.end()) {
    response->set_err(
        absl::StrCat("key template not found: ", request->template_name()));
    return grpc::Status::OK;
  }
  std::string templ;
  if (!it->second.SerializeToString(&templ)) {
    response->set_err("Failed to serialize template.");
    return grpc::Status::OK;
  }
  response->set_key_template(templ);
  return grpc::Status::OK;
}

// Generates a new keyset with one key from a template.
grpc::Status KeysetImpl::Generate(grpc::ServerContext* context,
                                    const KeysetGenerateRequest* request,
                                    KeysetGenerateResponse* response) {
  KeyTemplate key_template;
  if (!key_template.ParseFromString(request->template_())) {
    response->set_err("Could not parse the key template");
    return grpc::Status::OK;
  }
  auto handle_result = ::crypto::tink::KeysetHandle::GenerateNew(key_template);
  if (!handle_result.ok()) {
    response->set_err(std::string(handle_result.status().message()));
    return grpc::Status::OK;
  }
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!writer_result.ok()) {
    response->set_err(std::string(writer_result.status().message()));
    return grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(writer_result.value().get(),
                                             *handle_result.value());
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return grpc::Status::OK;
  }
  response->set_keyset(keyset.str());
  return grpc::Status::OK;
}

// Returns a public keyset for a given private keyset.
grpc::Status KeysetImpl::Public(grpc::ServerContext* context,
                                  const KeysetPublicRequest* request,
                                  KeysetPublicResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->private_keyset());
  if (!reader_result.ok()) {
    response->set_err(std::string(reader_result.status().message()));
    return grpc::Status::OK;
  }
  auto private_handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  if (!private_handle_result.ok()) {
    response->set_err(std::string(private_handle_result.status().message()));
    return grpc::Status::OK;
  }
  auto public_handle_result =
      private_handle_result.value()->GetPublicKeysetHandle();
  if (!public_handle_result.ok()) {
    response->set_err(std::string(public_handle_result.status().message()));
    return grpc::Status::OK;
  }
  std::stringbuf public_keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&public_keyset));
  if (!writer_result.ok()) {
    response->set_err(std::string(writer_result.status().message()));
    return grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(writer_result.value().get(),
                                             *public_handle_result.value());
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return grpc::Status::OK;
  }
  response->set_public_keyset(public_keyset.str());
  return grpc::Status::OK;
}

// Converts a keyset from binary to JSON format.
grpc::Status KeysetImpl::ToJson(grpc::ServerContext* context,
                                  const KeysetToJsonRequest* request,
                                  KeysetToJsonResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->keyset());
  if (!reader_result.ok()) {
    response->set_err(std::string(reader_result.status().message()));
    return grpc::Status::OK;
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  if (!handle_result.ok()) {
    response->set_err(std::string(handle_result.status().message()));
    return grpc::Status::OK;
  }
  std::stringbuf json_keyset;
  auto writer_result =
      JsonKeysetWriter::New(absl::make_unique<std::ostream>(&json_keyset));
  if (!writer_result.ok()) {
    response->set_err(std::string(writer_result.status().message()));
    return grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(writer_result.value().get(),
                                             *handle_result.value());
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return grpc::Status::OK;
  }
  response->set_json_keyset(json_keyset.str());
  return grpc::Status::OK;
}

// Converts a keyset from JSON to binary format.
grpc::Status KeysetImpl::FromJson(grpc::ServerContext* context,
                                    const KeysetFromJsonRequest* request,
                                    KeysetFromJsonResponse* response) {
  auto reader_result = JsonKeysetReader::New(request->json_keyset());
  if (!reader_result.ok()) {
    response->set_err(std::string(reader_result.status().message()));
    return grpc::Status::OK;
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  if (!handle_result.ok()) {
    response->set_err(std::string(handle_result.status().message()));
    return grpc::Status::OK;
  }
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!writer_result.ok()) {
    response->set_err(std::string(writer_result.status().message()));
    return grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(writer_result.value().get(),
                                             *handle_result.value());
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return grpc::Status::OK;
  }
  response->set_keyset(keyset.str());
  return grpc::Status::OK;
}

grpc::Status KeysetImpl::WriteEncrypted(
    grpc::ServerContext* context, const KeysetWriteEncryptedRequest* request,
    KeysetWriteEncryptedResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>>
      master_keyset_reader = BinaryKeysetReader::New(request->master_keyset());
  if (!master_keyset_reader.ok()) {
    response->set_err(std::string(master_keyset_reader.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> master_keyset_handle =
      CleartextKeysetHandle::Read(*std::move(master_keyset_reader));
  if (!master_keyset_handle.ok()) {
    response->set_err(std::string(master_keyset_handle.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<crypto::tink::Aead>> master_aead =
      (*master_keyset_handle)->GetPrimitive<crypto::tink::Aead>();
  if (!master_aead.ok()) {
    response->set_err(std::string(master_aead.status().message()));
    return grpc::Status::OK;
  }

  StatusOr<std::unique_ptr<KeysetReader>> keyset_reader =
      BinaryKeysetReader::New(request->keyset());
  if (!keyset_reader.ok()) {
    response->set_err(std::string(keyset_reader.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      CleartextKeysetHandle::Read(*std::move(keyset_reader));
  if (!keyset_handle.ok()) {
    response->set_err(std::string(keyset_handle.status().message()));
    return grpc::Status::OK;
  }

  std::stringbuf encrypted_keyset;
  std::unique_ptr<KeysetWriter> keyset_writer;

  if (request->keyset_writer_type() == KEYSET_WRITER_BINARY) {
    StatusOr<std::unique_ptr<BinaryKeysetWriter>> binary_keyset_writer =
        BinaryKeysetWriter::New(
            absl::make_unique<std::ostream>(&encrypted_keyset));
    if (!binary_keyset_writer.ok()) {
      response->set_err(std::string(binary_keyset_writer.status().message()));
      return grpc::Status::OK;
    }
    keyset_writer = *std::move(binary_keyset_writer);
  } else if (request->keyset_writer_type() == KEYSET_WRITER_JSON) {
    StatusOr<std::unique_ptr<JsonKeysetWriter>> json_keyset_writer =
        JsonKeysetWriter::New(
            absl::make_unique<std::ostream>(&encrypted_keyset));
    if (!json_keyset_writer.ok()) {
      response->set_err(std::string(json_keyset_writer.status().message()));
      return grpc::Status::OK;
    }
    keyset_writer = *std::move(json_keyset_writer);
  } else {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "unknown keyset_writer_type");
  }

  if (request->has_associated_data()) {
    crypto::tink::util::Status status =
        (*keyset_handle)
            ->WriteWithAssociatedData(keyset_writer.get(), **master_aead,
                                      request->associated_data().value());
    if (!status.ok()) {
      response->set_err(std::string(status.message()));
      return grpc::Status::OK;
    }
  } else {
    crypto::tink::util::Status status =
        (*keyset_handle)->Write(keyset_writer.get(), **master_aead);
    if (!status.ok()) {
      response->set_err(std::string(status.message()));
      return grpc::Status::OK;
    }
  }
  response->set_encrypted_keyset(encrypted_keyset.str());
  return grpc::Status::OK;
}

grpc::Status KeysetImpl::ReadEncrypted(
    grpc::ServerContext* context, const KeysetReadEncryptedRequest* request,
    KeysetReadEncryptedResponse* response) {
  StatusOr<std::unique_ptr<KeysetReader>> master_keyset_reader =
      BinaryKeysetReader::New(request->master_keyset());
  if (!master_keyset_reader.ok()) {
    response->set_err(std::string(master_keyset_reader.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<KeysetHandle>> master_keyset_handle =
      CleartextKeysetHandle::Read(*std::move(master_keyset_reader));
  if (!master_keyset_handle.ok()) {
    response->set_err(std::string(master_keyset_handle.status().message()));
    return grpc::Status::OK;
  }
  StatusOr<std::unique_ptr<crypto::tink::Aead>> master_aead =
      (*master_keyset_handle)->GetPrimitive<crypto::tink::Aead>();
  if (!master_aead.ok()) {
    response->set_err(std::string(master_aead.status().message()));
    return grpc::Status::OK;
  }

  std::unique_ptr<KeysetReader> keyset_reader;
  if (request->keyset_reader_type() == KEYSET_READER_BINARY) {
    StatusOr<std::unique_ptr<KeysetReader>> binary_keyset_reader =
        BinaryKeysetReader::New(request->encrypted_keyset());
    if (!binary_keyset_reader.ok()) {
      response->set_err(std::string(binary_keyset_reader.status().message()));
      return grpc::Status::OK;
    }
    keyset_reader = *std::move(binary_keyset_reader);
  } else if (request->keyset_reader_type() == KEYSET_READER_JSON) {
    StatusOr<std::unique_ptr<KeysetReader>> json_keyset_reader =
        JsonKeysetReader::New(request->encrypted_keyset());
    if (!json_keyset_reader.ok()) {
      response->set_err(std::string(json_keyset_reader.status().message()));
      return grpc::Status::OK;
    }
    keyset_reader = *std::move(json_keyset_reader);
  } else {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "unknown keyset_writer_type");
  }

  std::unique_ptr<KeysetHandle> keyset_handle;
  if (request->has_associated_data()) {
    StatusOr<std::unique_ptr<KeysetHandle>> read_result =
        ::crypto::tink::KeysetHandle::ReadWithAssociatedData(
            std::move(keyset_reader), **master_aead,
            request->associated_data().value());
    if (!read_result.ok()) {
      response->set_err(std::string(read_result.status().message()));
      return grpc::Status::OK;
    }
    keyset_handle = *std::move(read_result);
  } else {
    StatusOr<std::unique_ptr<KeysetHandle>> read_result =
        ::crypto::tink::KeysetHandle::Read(std::move(keyset_reader),
                                           **master_aead);
    if (!read_result.ok()) {
      response->set_err(std::string(read_result.status().message()));
      return grpc::Status::OK;
    }
    keyset_handle = *std::move(read_result);
  }

  std::stringbuf keyset;
  StatusOr<std::unique_ptr<BinaryKeysetWriter>> keyset_writer =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!keyset_writer.ok()) {
    response->set_err(std::string(keyset_writer.status().message()));
    return grpc::Status::OK;
  }
  crypto::tink::util::Status status =
      CleartextKeysetHandle::Write(keyset_writer->get(), *keyset_handle);
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return grpc::Status::OK;
  }
  response->set_keyset(keyset.str());
  return grpc::Status::OK;
}

}  // namespace tink_testing_api
