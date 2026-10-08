// Copyright 2020 Google LLC
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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig2026;
import com.google.crypto.tink.testing.proto.AeadDecryptRequest;
import com.google.crypto.tink.testing.proto.AeadDecryptResponse;
import com.google.crypto.tink.testing.proto.AeadEncryptRequest;
import com.google.crypto.tink.testing.proto.AeadEncryptResponse;
import com.google.crypto.tink.testing.proto.AeadGrpc.AeadImplBase;
import com.google.crypto.tink.testing.proto.AnnotatedKeyset;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;

/** Implements a gRPC Aead Testing service. */
public final class AeadServiceImpl extends AeadImplBase {

  public AeadServiceImpl() throws GeneralSecurityException {}

  private static Aead getAead(AnnotatedKeyset annotatedKeyset) throws GeneralSecurityException {
    try {
      return Util.parseBinaryProtoKeyset(annotatedKeyset, AeadConfig2026.get())
          .getPrimitive(AeadConfig2026.get(), Aead.class);
    } catch (GeneralSecurityException e) {
      // Legacy KMS keys (KmsAeadKey and KmsEnvelopeAeadKey) are not in AeadConfig2026.
      return Util.parseBinaryProtoKeyset(annotatedKeyset, RegistryConfiguration.get())
          .getPrimitive(RegistryConfiguration.get(), Aead.class);
    }
  }

  @Override
  public void create(CreationRequest request, StreamObserver<CreationResponse> responseObserver) {
    try {
      Aead unused = getAead(request.getAnnotatedKeyset());
    } catch (GeneralSecurityException e) {
      responseObserver.onNext(CreationResponse.newBuilder().setErr(e.toString()).build());
      responseObserver.onCompleted();
      return;
    }
    responseObserver.onNext(CreationResponse.getDefaultInstance());
    responseObserver.onCompleted();
  }

  AeadEncryptResponse encrypt(AeadEncryptRequest request) throws GeneralSecurityException {
    Aead aead = getAead(request.getAnnotatedKeyset());
    try {
      byte[] ciphertext =
          aead.encrypt(
              request.getPlaintext().toByteArray(), request.getAssociatedData().toByteArray());
      return AeadEncryptResponse.newBuilder()
          .setCiphertext(ByteString.copyFrom(ciphertext))
          .build();
    } catch (GeneralSecurityException e) {
      return AeadEncryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  /** Encrypts a message. */
  @Override
  public void encrypt(
      AeadEncryptRequest request, StreamObserver<AeadEncryptResponse> responseObserver) {
    try {
      AeadEncryptResponse response = encrypt(request);
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }

  AeadDecryptResponse decrypt(AeadDecryptRequest request) throws GeneralSecurityException {
    Aead aead = getAead(request.getAnnotatedKeyset());
    try {
      byte[] plaintext =
          aead.decrypt(
              request.getCiphertext().toByteArray(), request.getAssociatedData().toByteArray());
      return AeadDecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(plaintext)).build();
    } catch (GeneralSecurityException e) {
      return AeadDecryptResponse.newBuilder().setErr(e.toString()).build();
    }
  }

  /** Decrypts a message. */
  @Override
  public void decrypt(
      AeadDecryptRequest request, StreamObserver<AeadDecryptResponse> responseObserver) {
    try {
      AeadDecryptResponse response = decrypt(request);
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    } catch (Exception e) {
      responseObserver.onError(e);
    }
  }
}
