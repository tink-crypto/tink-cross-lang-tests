// Copyright 2021 Google LLC
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

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.crypto.tink.testing.proto.DeriveKeysetRequest;
import com.google.crypto.tink.testing.proto.DeriveKeysetResponse;
import com.google.crypto.tink.testing.proto.KeysetDeriverGrpc.KeysetDeriverImplBase;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;

/** Implements a gRPC Testing service for Keyset Derivation. */
public final class KeysetDeriverServiceImpl extends KeysetDeriverImplBase {

  public KeysetDeriverServiceImpl() throws GeneralSecurityException {}

  @Override
  public void create(CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    Util.createPrimitiveForRpc(request, responseObserver, KeysetDeriver.class);
  }

  private DeriveKeysetResponse deriveKeyset(DeriveKeysetRequest request)
      throws GeneralSecurityException {
    KeysetDeriver deriver =
        Util.parseBinaryProtoKeyset(request.getAnnotatedKeyset())
            .getPrimitive(RegistryConfiguration.get(), KeysetDeriver.class);
    try {
      KeysetHandle derivedKeysetHandle = deriver.deriveKeyset(request.getSalt().toByteArray());
      byte[] serializedDerivedKeyset =
          TinkProtoKeysetFormat.serializeKeyset(derivedKeysetHandle, InsecureSecretKeyAccess.get());
      return DeriveKeysetResponse.newBuilder()
          .setDerivedKeyset(ByteString.copyFrom(serializedDerivedKeyset))
          .build();
    } catch (GeneralSecurityException e) {
      return DeriveKeysetResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  @Override
  public void deriveKeyset(
      DeriveKeysetRequest request, StreamObserver<DeriveKeysetResponse> responseObserver) {
    try {
      DeriveKeysetResponse response = deriveKeyset(request);
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }
}
