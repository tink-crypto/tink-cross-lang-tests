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

#include "absl/status/statusor.h"
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include "tink/signature/prehash.h"
#include "tink/signature/sign_prehash.h"
#include "create.h"

namespace tink_testing_api {

::grpc::Status SignPrehashImpl::CreatePrehash(
    grpc::ServerContext* context, const CreationRequest* request,
    CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::Prehash>(request, response);
}

::grpc::Status SignPrehashImpl::CreatePrehashSigner(
    grpc::ServerContext* context, const CreationRequest* request,
    CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::SignPrehash>(request, response);
}

::grpc::Status SignPrehashImpl::ComputePrehash(
    grpc::ServerContext* context,
    const ComputePrehashRequest* request,
    ComputePrehashResponse* response) {
  absl::StatusOr<std::unique_ptr<crypto::tink::Prehash>> prehash_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::Prehash>(
          request->public_annotated_keyset());
  if (!prehash_result.ok()) {
    response->set_err(prehash_result.status().message());
    return ::grpc::Status::OK;
  }
  auto compute_result = prehash_result.value()->Compute(request->data());
  if (!compute_result.ok()) {
    response->set_err(compute_result.status().message());
    return ::grpc::Status::OK;
  }
  response->set_prehash(compute_result.value());
  return ::grpc::Status::OK;
}

::grpc::Status SignPrehashImpl::SignPrehash(
    grpc::ServerContext* context,
    const SignPrehashRequest* request,
    SignPrehashResponse* response) {
  absl::StatusOr<std::unique_ptr<crypto::tink::SignPrehash>> signer_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::SignPrehash>(
          request->private_annotated_keyset());
  if (!signer_result.ok()) {
    response->set_err(signer_result.status().message());
    return ::grpc::Status::OK;
  }
  auto sign_result = signer_result.value()->Sign(request->prehash());
  if (!sign_result.ok()) {
    response->set_err(sign_result.status().message());
    return ::grpc::Status::OK;
  }
  response->set_signature(sign_result.value());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
