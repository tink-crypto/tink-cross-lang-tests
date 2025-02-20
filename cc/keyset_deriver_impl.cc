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

#include <memory>
#include <string>
#include <utility>

#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/keyset_handle.h"
#include "create.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::KeysetReader;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::grpc::ServerContext;

::grpc::Status KeysetDeriverImpl::Create(grpc::ServerContext* context,
                                         const CreationRequest* request,
                                         CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::KeysetDeriver>(request, response);
}

grpc::Status KeysetDeriverImpl::DeriveKeyset(
    ServerContext* context, const DeriveKeysetRequest* request,
    DeriveKeysetResponse* response) {
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(request->annotated_keyset().serialized_keyset());
  if (!reader.ok()) {
    response->set_err(std::string(reader.status().message()));
    return grpc::Status::OK;
  }
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      CleartextKeysetHandle::Read(std::move(*reader));
  if (!keyset_handle.ok()) {
    response->set_err(std::string(keyset_handle.status().message()));
    return grpc::Status::OK;
  }
  absl::StatusOr<std::unique_ptr<crypto::tink::KeysetDeriver>> deriver =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::KeysetDeriver>(
              crypto::tink::ConfigGlobalRegistry());
  if (!deriver.ok()) {
    response->set_err(std::string(deriver.status().message()));
    return grpc::Status::OK;
  }
  absl::StatusOr<std::unique_ptr<KeysetHandle>> derived_keyset_handle =
      (*deriver)->DeriveKeyset(request->salt());
  if (!derived_keyset_handle.ok()) {
    response->set_err(std::string(derived_keyset_handle.status().message()));
    return grpc::Status::OK;
  }
  std::stringbuf derived_keyset;
  absl::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(std::make_unique<std::ostream>(&derived_keyset));
  if (!writer.ok()) {
    response->set_err(std::string(writer.status().message()));
    return grpc::Status::OK;
  }
  Status status =
      CleartextKeysetHandle::Write((*writer).get(), **derived_keyset_handle);
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return grpc::Status::OK;
  }
  response->set_derived_keyset(derived_keyset.str());
  return grpc::Status::OK;
}

}  // namespace tink_testing_api
