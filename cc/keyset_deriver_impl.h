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

#ifndef THIRD_PARTY_TINK_TESTING_CC_KEYSET_DERIVER_IMPL_H_
#define THIRD_PARTY_TINK_TESTING_CC_KEYSET_DERIVER_IMPL_H_

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>

#include "protos/testing_api.grpc.pb.h"

namespace tink_testing_api {

// A gRPC Testing service for KeysetDeriver.
class KeysetDeriverImpl final : public KeysetDeriver::Service {
 public:
  grpc::Status Create(grpc::ServerContext* context,
                      const CreationRequest* request,
                      CreationResponse* response) override;

  grpc::Status DeriveKeyset(grpc::ServerContext* context,
                            const DeriveKeysetRequest* request,
                            DeriveKeysetResponse* response) override;
};

}  // namespace tink_testing_api

#endif  // THIRD_PARTY_TINK_TESTING_CC_KEYSET_DERIVER_IMPL_H_