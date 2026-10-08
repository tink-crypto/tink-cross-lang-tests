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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Configuration;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.config.TinkConfig2026;
import com.google.crypto.tink.signature.CompositeMlDsaParameters;
import com.google.crypto.tink.testing.proto.KeysetFromJsonRequest;
import com.google.crypto.tink.testing.proto.KeysetFromJsonResponse;
import com.google.crypto.tink.testing.proto.KeysetGenerateRequest;
import com.google.crypto.tink.testing.proto.KeysetGenerateResponse;
import com.google.crypto.tink.testing.proto.KeysetGrpc.KeysetImplBase;
import com.google.crypto.tink.testing.proto.KeysetPublicRequest;
import com.google.crypto.tink.testing.proto.KeysetPublicResponse;
import com.google.crypto.tink.testing.proto.KeysetReadEncryptedRequest;
import com.google.crypto.tink.testing.proto.KeysetReadEncryptedResponse;
import com.google.crypto.tink.testing.proto.KeysetReaderType;
import com.google.crypto.tink.testing.proto.KeysetTemplateRequest;
import com.google.crypto.tink.testing.proto.KeysetTemplateResponse;
import com.google.crypto.tink.testing.proto.KeysetToJsonRequest;
import com.google.crypto.tink.testing.proto.KeysetToJsonResponse;
import com.google.crypto.tink.testing.proto.KeysetWriteEncryptedRequest;
import com.google.crypto.tink.testing.proto.KeysetWriteEncryptedResponse;
import com.google.crypto.tink.testing.proto.KeysetWriterType;
import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** Implement a gRPC Keyset Testing service. */
public final class KeysetServiceImpl extends KeysetImplBase {

  private static final Map<String, Parameters> compositeMlDsaParameters =
      createCompositeMlDsaParameters();

  private static Map<String, Parameters> createCompositeMlDsaParameters() {
    Map<String, Parameters> params = new HashMap<>();
    try {
      params.put(
          "COMPOSITE_MLDSA_65_ED25519",
          CompositeMlDsaParameters.builder()
              .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
              .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ED25519)
              .setVariant(CompositeMlDsaParameters.Variant.TINK)
              .build());
      params.put(
          "COMPOSITE_MLDSA_65_ECDSA_P256",
          CompositeMlDsaParameters.builder()
              .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
              .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P256)
              .setVariant(CompositeMlDsaParameters.Variant.TINK)
              .build());
      params.put(
          "COMPOSITE_MLDSA_87_ECDSA_P384",
          CompositeMlDsaParameters.builder()
              .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_87)
              .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.ECDSA_P384)
              .setVariant(CompositeMlDsaParameters.Variant.TINK)
              .build());
      params.put(
          "COMPOSITE_MLDSA_65_RSA3072_PKCS1",
          CompositeMlDsaParameters.builder()
              .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_65)
              .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.RSA3072_PKCS1)
              .setVariant(CompositeMlDsaParameters.Variant.TINK)
              .build());
      params.put(
          "COMPOSITE_MLDSA_87_RSA4096_PSS",
          CompositeMlDsaParameters.builder()
              .setMlDsaInstance(CompositeMlDsaParameters.MlDsaInstance.ML_DSA_87)
              .setClassicalAlgorithm(CompositeMlDsaParameters.ClassicalAlgorithm.RSA4096_PSS)
              .setVariant(CompositeMlDsaParameters.Variant.TINK)
              .build());
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
    return Collections.unmodifiableMap(params);
  }

  private final Configuration config;

  public KeysetServiceImpl(Configuration config) {
    this.config = config;
  }

  public KeysetServiceImpl() throws GeneralSecurityException {
    this(TinkConfig2026.get());
  }

  @Override
  public void getTemplate(
      KeysetTemplateRequest request, StreamObserver<KeysetTemplateResponse> responseObserver) {
    KeysetTemplateResponse response;
    try {
      Parameters parameters;
      if (compositeMlDsaParameters.containsKey(request.getTemplateName())) {
        parameters = compositeMlDsaParameters.get(request.getTemplateName());
      } else {
        KeyTemplate template = KeyTemplates.get(request.getTemplateName());
        parameters = template.toParameters();
      }
      response =
          KeysetTemplateResponse.newBuilder()
              .setKeyTemplate(
                  ByteString.copyFrom(TinkProtoParametersFormat.serialize(parameters, config)))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetTemplateResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  private static byte[] generateKeyset(byte[] template, Configuration config)
      throws GeneralSecurityException {
    Parameters parameters = TinkProtoParametersFormat.parse(template, RegistryConfiguration.get());
    KeysetHandle keysetHandle;
    try {
      keysetHandle = KeysetHandle.generateNew(parameters, RegistryConfiguration.get());
    } catch (GeneralSecurityException e) {
      if (e.getMessage() != null
          && e.getMessage().startsWith("No key manager found for key type")) {
        parameters = TinkProtoParametersFormat.parse(template, config);
        keysetHandle = KeysetHandle.generateNew(parameters, config);
        return TinkProtoKeysetFormat.serializeKeyset(
            keysetHandle, InsecureSecretKeyAccess.get(), config);
      }
      throw e;
    }
    return TinkProtoKeysetFormat.serializeKeyset(
        keysetHandle, InsecureSecretKeyAccess.get(), RegistryConfiguration.get());
  }

  @Override
  public void generate(
      KeysetGenerateRequest request, StreamObserver<KeysetGenerateResponse> responseObserver) {
    KeysetGenerateResponse response;
    try {
      byte[] serializedKeyset = generateKeyset(request.getTemplate().toByteArray(), config);
      response =
          KeysetGenerateResponse.newBuilder()
              .setKeyset(ByteString.copyFrom(serializedKeyset))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetGenerateResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  private static byte[] getPublicKeyset(byte[] privateKeyset, Configuration config)
      throws GeneralSecurityException {
    KeysetHandle privateKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            privateKeyset, InsecureSecretKeyAccess.get(), config);
    KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
    return TinkProtoKeysetFormat.serializeKeyset(
        publicKeysetHandle, InsecureSecretKeyAccess.get(), config);
  }

  @Override
  public void public_(
      KeysetPublicRequest request, StreamObserver<KeysetPublicResponse> responseObserver) {
    KeysetPublicResponse response;
    try {
      byte[] serializedPublicKeyset =
          getPublicKeyset(request.getPrivateKeyset().toByteArray(), config);
      response =
          KeysetPublicResponse.newBuilder()
              .setPublicKeyset(ByteString.copyFrom(serializedPublicKeyset))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetPublicResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  private static String keysetToJson(byte[] keyset, Configuration config)
      throws GeneralSecurityException {
    KeysetHandle keysetHandle =
        TinkProtoKeysetFormat.parseKeyset(keyset, InsecureSecretKeyAccess.get(), config);
    return TinkJsonProtoKeysetFormat.serializeKeyset(
        keysetHandle, config, InsecureSecretKeyAccess.get());
  }

  @Override
  public void toJson(
      KeysetToJsonRequest request, StreamObserver<KeysetToJsonResponse> responseObserver) {
    KeysetToJsonResponse response;
    try {
      String jsonKeyset = keysetToJson(request.getKeyset().toByteArray(), config);
      response = KeysetToJsonResponse.newBuilder().setJsonKeyset(jsonKeyset).build();
    } catch (GeneralSecurityException e) {
      response = KeysetToJsonResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  private static byte[] keysetFromJson(String jsonKeyset, Configuration config)
      throws GeneralSecurityException {
    KeysetHandle keysetHandle =
        TinkJsonProtoKeysetFormat.parseKeyset(
            jsonKeyset, config, InsecureSecretKeyAccess.get());
    return TinkProtoKeysetFormat.serializeKeyset(
        keysetHandle, InsecureSecretKeyAccess.get(), config);
  }

  @Override
  public void fromJson(
      KeysetFromJsonRequest request, StreamObserver<KeysetFromJsonResponse> responseObserver) {
    KeysetFromJsonResponse response;
    try {
      byte[] serializedKeyset = keysetFromJson(request.getJsonKeyset(), config);
      response =
          KeysetFromJsonResponse.newBuilder()
              .setKeyset(ByteString.copyFrom(serializedKeyset))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetFromJsonResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  private static byte[] readEncryptedKeyset(
      KeysetReadEncryptedRequest request, Aead masterAead, Configuration config)
      throws GeneralSecurityException {
    byte[] associatedData = request.getAssociatedData().getValue().toByteArray();
    KeysetHandle keysetHandle;
    if (request.getKeysetReaderType() == KeysetReaderType.KEYSET_READER_BINARY) {
      keysetHandle =
          TinkProtoKeysetFormat.parseEncryptedKeyset(
              request.getEncryptedKeyset().toByteArray(), masterAead, associatedData, config);
    } else if (request.getKeysetReaderType() == KeysetReaderType.KEYSET_READER_JSON) {
      keysetHandle =
          TinkJsonProtoKeysetFormat.parseEncryptedKeyset(
              request.getEncryptedKeyset().toStringUtf8(), masterAead, associatedData, config);
    } else {
      throw new IllegalArgumentException("unknown keyset reader type");
    }
    return TinkProtoKeysetFormat.serializeKeyset(
        keysetHandle, InsecureSecretKeyAccess.get(), config);
  }

  @Override
  public void readEncrypted(
      KeysetReadEncryptedRequest request,
      StreamObserver<KeysetReadEncryptedResponse> responseObserver) {
    KeysetReadEncryptedResponse response;
    try {
      // get masterAead
      KeysetHandle masterKeysetHandle =
          TinkProtoKeysetFormat.parseKeyset(
              request.getMasterKeyset().toByteArray(),
              InsecureSecretKeyAccess.get(),
              config);
      Aead masterAead = masterKeysetHandle.getPrimitive(config, Aead.class);

      byte[] keyset = readEncryptedKeyset(request, masterAead, config);
      response =
          KeysetReadEncryptedResponse.newBuilder().setKeyset(ByteString.copyFrom(keyset)).build();
    } catch (GeneralSecurityException e) {
      response = KeysetReadEncryptedResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }

  private static byte[] writeEncryptedKeyset(
      KeysetWriteEncryptedRequest request, Aead masterAead, Configuration config)
      throws GeneralSecurityException {
    KeysetHandle keysetHandle =
        TinkProtoKeysetFormat.parseKeyset(
            request.getKeyset().toByteArray(), InsecureSecretKeyAccess.get(), config);
    byte[] associatedData = request.getAssociatedData().getValue().toByteArray();
    if (request.getKeysetWriterType() == KeysetWriterType.KEYSET_WRITER_BINARY) {
      return TinkProtoKeysetFormat.serializeEncryptedKeyset(
          keysetHandle, masterAead, associatedData, config);
    } else if (request.getKeysetWriterType() == KeysetWriterType.KEYSET_WRITER_JSON) {
      return TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
              keysetHandle, masterAead, associatedData, config)
          .getBytes(UTF_8);
    } else {
      throw new IllegalArgumentException("unknown keyset writer type");
    }
  }

  @Override
  public void writeEncrypted(
      KeysetWriteEncryptedRequest request,
      StreamObserver<KeysetWriteEncryptedResponse> responseObserver) {
    KeysetWriteEncryptedResponse response;
    try {
      // get masterAead
      KeysetHandle masterKeysetHandle =
          TinkProtoKeysetFormat.parseKeyset(
              request.getMasterKeyset().toByteArray(),
              InsecureSecretKeyAccess.get(),
              config);
      Aead masterAead = masterKeysetHandle.getPrimitive(config, Aead.class);

      byte[] keyset = writeEncryptedKeyset(request, masterAead, config);
      response =
          KeysetWriteEncryptedResponse.newBuilder()
              .setEncryptedKeyset(ByteString.copyFrom(keyset))
              .build();
    } catch (GeneralSecurityException e) {
      response = KeysetWriteEncryptedResponse.newBuilder().setErr(e.toString()).build();
    }
    responseObserver.onNext(response);
    responseObserver.onCompleted();
  }
}
