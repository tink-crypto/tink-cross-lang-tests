// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.testing;

import com.google.crypto.tink.testing.proto.ComputePrehashRequest;
import com.google.crypto.tink.testing.proto.ComputePrehashResponse;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.crypto.tink.testing.proto.SignPrehashGrpc.SignPrehashImplBase;
import com.google.crypto.tink.testing.proto.SignPrehashRequest;
import com.google.crypto.tink.testing.proto.SignPrehashResponse;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;

/** Implements a gRPC SignPrehash Testing service. */
public final class SignPrehashServiceImpl extends SignPrehashImplBase {

  public SignPrehashServiceImpl() throws GeneralSecurityException {}

  @Override
  public void createPrehash(
      CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    responseObserver.onNext(
        CreationResponse.newBuilder().setErr("Unimplemented in Java").build());
    responseObserver.onCompleted();
  }

  @Override
  public void createPrehashSigner(
      CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    responseObserver.onNext(
        CreationResponse.newBuilder().setErr("Unimplemented in Java").build());
    responseObserver.onCompleted();
  }

  @Override
  public void computePrehash(
      ComputePrehashRequest request,
      StreamObserver<ComputePrehashResponse> responseObserver) {
    responseObserver.onNext(
        ComputePrehashResponse.newBuilder().setErr("Unimplemented in Java").build());
    responseObserver.onCompleted();
  }

  @Override
  public void signPrehash(
      SignPrehashRequest request,
      StreamObserver<SignPrehashResponse> responseObserver) {
    responseObserver.onNext(
        SignPrehashResponse.newBuilder().setErr("Unimplemented in Java").build());
    responseObserver.onCompleted();
  }
}
