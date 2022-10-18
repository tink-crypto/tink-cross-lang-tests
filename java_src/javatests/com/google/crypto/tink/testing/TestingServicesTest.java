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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.daead.AesSivKeyManager;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.prf.HmacPrfKeyManager;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKeyManager;
import com.google.crypto.tink.testing.proto.AeadDecryptRequest;
import com.google.crypto.tink.testing.proto.AeadDecryptResponse;
import com.google.crypto.tink.testing.proto.AeadEncryptRequest;
import com.google.crypto.tink.testing.proto.AeadEncryptResponse;
import com.google.crypto.tink.testing.proto.AeadGrpc;
import com.google.crypto.tink.testing.proto.AnnotatedKeyset;
import com.google.crypto.tink.testing.proto.BytesValue;
import com.google.crypto.tink.testing.proto.ComputeMacRequest;
import com.google.crypto.tink.testing.proto.ComputeMacResponse;
import com.google.crypto.tink.testing.proto.CreationRequest;
import com.google.crypto.tink.testing.proto.CreationResponse;
import com.google.crypto.tink.testing.proto.DeterministicAeadDecryptRequest;
import com.google.crypto.tink.testing.proto.DeterministicAeadDecryptResponse;
import com.google.crypto.tink.testing.proto.DeterministicAeadEncryptRequest;
import com.google.crypto.tink.testing.proto.DeterministicAeadEncryptResponse;
import com.google.crypto.tink.testing.proto.DeterministicAeadGrpc;
import com.google.crypto.tink.testing.proto.KeysetFromJsonRequest;
import com.google.crypto.tink.testing.proto.KeysetFromJsonResponse;
import com.google.crypto.tink.testing.proto.KeysetGenerateRequest;
import com.google.crypto.tink.testing.proto.KeysetGenerateResponse;
import com.google.crypto.tink.testing.proto.KeysetGrpc;
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
import com.google.crypto.tink.testing.proto.MacGrpc;
import com.google.crypto.tink.testing.proto.MetadataGrpc;
import com.google.crypto.tink.testing.proto.PrfSetComputeRequest;
import com.google.crypto.tink.testing.proto.PrfSetComputeResponse;
import com.google.crypto.tink.testing.proto.PrfSetGrpc;
import com.google.crypto.tink.testing.proto.PrfSetKeyIdsRequest;
import com.google.crypto.tink.testing.proto.PrfSetKeyIdsResponse;
import com.google.crypto.tink.testing.proto.ServerInfoRequest;
import com.google.crypto.tink.testing.proto.ServerInfoResponse;
import com.google.crypto.tink.testing.proto.StreamingAeadDecryptRequest;
import com.google.crypto.tink.testing.proto.StreamingAeadDecryptResponse;
import com.google.crypto.tink.testing.proto.StreamingAeadEncryptRequest;
import com.google.crypto.tink.testing.proto.StreamingAeadEncryptResponse;
import com.google.crypto.tink.testing.proto.StreamingAeadGrpc;
import com.google.crypto.tink.testing.proto.VerifyMacRequest;
import com.google.crypto.tink.testing.proto.VerifyMacResponse;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import java.util.Optional;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class TestingServicesTest {
  private Server server;
  private ManagedChannel channel;
  MetadataGrpc.MetadataBlockingStub metadataStub;
  KeysetGrpc.KeysetBlockingStub keysetStub;
  AeadGrpc.AeadBlockingStub aeadStub;
  DeterministicAeadGrpc.DeterministicAeadBlockingStub daeadStub;
  StreamingAeadGrpc.StreamingAeadBlockingStub streamingAeadStub;
  MacGrpc.MacBlockingStub macStub;
  PrfSetGrpc.PrfSetBlockingStub prfSetStub;

  @Before
  public void setUp() throws Exception {
    TinkConfig.register();
    String serverName = InProcessServerBuilder.generateName();
    server =
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(new MetadataServiceImpl())
            .addService(new KeysetServiceImpl())
            .addService(new AeadServiceImpl())
            .addService(new DeterministicAeadServiceImpl())
            .addService(new StreamingAeadServiceImpl())
            .addService(new MacServiceImpl())
            .addService(new PrfSetServiceImpl())
            .build()
            .start();
    channel = InProcessChannelBuilder.forName(serverName).directExecutor().build();
    metadataStub = MetadataGrpc.newBlockingStub(channel);
    keysetStub = KeysetGrpc.newBlockingStub(channel);
    aeadStub = AeadGrpc.newBlockingStub(channel);
    daeadStub = DeterministicAeadGrpc.newBlockingStub(channel);
    streamingAeadStub = StreamingAeadGrpc.newBlockingStub(channel);
    macStub = MacGrpc.newBlockingStub(channel);
    prfSetStub = PrfSetGrpc.newBlockingStub(channel);
  }

  @After
  public void tearDown() throws Exception {
    assertThat(channel.shutdown().awaitTermination(5, SECONDS)).isTrue();
    assertThat(server.shutdown().awaitTermination(5, SECONDS)).isTrue();
  }

  private static KeysetGenerateResponse generateKeyset(
      KeysetGrpc.KeysetBlockingStub keysetStub, byte[] template) {
    KeysetGenerateRequest genRequest =
        KeysetGenerateRequest.newBuilder().setTemplate(ByteString.copyFrom(template)).build();
    return keysetStub.generate(genRequest);
  }

  private static KeysetToJsonResponse keysetToJson(
      KeysetGrpc.KeysetBlockingStub keysetStub, byte[] keyset) {
    KeysetToJsonRequest request =
        KeysetToJsonRequest.newBuilder().setKeyset(ByteString.copyFrom(keyset)).build();
    return keysetStub.toJson(request);
  }

  private static KeysetFromJsonResponse keysetFromJson(
      KeysetGrpc.KeysetBlockingStub keysetStub, String jsonKeyset) {
    KeysetFromJsonRequest request =
        KeysetFromJsonRequest.newBuilder().setJsonKeyset(jsonKeyset).build();
    return keysetStub.fromJson(request);
  }

  @Test
  public void template_success() throws Exception {
    KeysetTemplateRequest request =
        KeysetTemplateRequest.newBuilder().setTemplateName("AES256_GCM").build();
    KeysetTemplateResponse response = keysetStub.getTemplate(request);
    assertThat(response.getErr()).isEmpty();
    KeyTemplate template =
        KeyTemplateProtoConverter.fromByteArray(response.getKeyTemplate().toByteArray());
    assertThat(template.getTypeUrl()).isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmKey");
  }

  @Test
  public void template_not_found() throws Exception {
    KeysetTemplateRequest request =
        KeysetTemplateRequest.newBuilder().setTemplateName("UNKNOWN_TEMPLATE").build();
    KeysetTemplateResponse response = keysetStub.getTemplate(request);
    assertThat(response.getErr()).isNotEmpty();
  }

  @Test
  public void fromJson_success() throws Exception {
    String jsonKeyset =
        ""
            + "{"
            + "  \"primaryKeyId\": 42,"
            + "  \"key\": ["
            + "    {"
            + "      \"keyData\": {"
            + "        \"typeUrl\": \"type.googleapis.com/google.crypto.tink.AesGcmKey\","
            + "        \"keyMaterialType\": \"SYMMETRIC\","
            + "        \"value\": \"AFakeTestKeyValue1234567\""
            + "      },"
            + "      \"outputPrefixType\": \"TINK\","
            + "      \"keyId\": 42,"
            + "      \"status\": \"ENABLED\""
            + "    }"
            + "  ]"
            + "}";
    KeysetFromJsonResponse fromResponse = keysetFromJson(keysetStub, jsonKeyset);
    assertThat(fromResponse.getErr()).isEmpty();
    byte[] serializedKeyset = fromResponse.getKeyset().toByteArray();

    KeysetHandle parseKeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertThat(parseKeysetHandle.getPrimary().getId()).isEqualTo(42);
  }

  @Test
  public void toFromJson_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("AES128_GCM"));

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    KeysetToJsonResponse toResponse = keysetToJson(keysetStub, keyset);
    assertThat(toResponse.getErr()).isEmpty();
    String jsonKeyset = toResponse.getJsonKeyset();

    KeysetFromJsonResponse fromResponse = keysetFromJson(keysetStub, jsonKeyset);
    assertThat(fromResponse.getErr()).isEmpty();
    byte[] output = fromResponse.getKeyset().toByteArray();

    assertThat(output).isEqualTo(keyset);
  }

  private static KeysetReadEncryptedResponse keysetReadEncrypted(
      KeysetGrpc.KeysetBlockingStub keysetStub,
      byte[] encryptedKeyset,
      byte[] masterKeyset,
      Optional<byte[]> associatedData) {
    KeysetReadEncryptedRequest.Builder requestBuilder =
        KeysetReadEncryptedRequest.newBuilder()
            .setEncryptedKeyset(ByteString.copyFrom(encryptedKeyset))
            .setMasterKeyset(ByteString.copyFrom(masterKeyset))
            .setKeysetReaderType(KeysetReaderType.KEYSET_READER_BINARY);
    if (associatedData.isPresent()) {
      requestBuilder.setAssociatedData(
          BytesValue.newBuilder().setValue(ByteString.copyFrom(associatedData.get())).build());
    }
    return keysetStub.readEncrypted(requestBuilder.build());
  }

  private static KeysetWriteEncryptedResponse keysetWriteEncrypted(
      KeysetGrpc.KeysetBlockingStub keysetStub,
      byte[] keyset,
      byte[] masterKeyset,
      Optional<byte[]> associatedData) {
    KeysetWriteEncryptedRequest.Builder requestBuilder =
        KeysetWriteEncryptedRequest.newBuilder()
            .setKeyset(ByteString.copyFrom(keyset))
            .setMasterKeyset(ByteString.copyFrom(masterKeyset))
            .setKeysetWriterType(KeysetWriterType.KEYSET_WRITER_BINARY);
    if (associatedData.isPresent()) {
      requestBuilder.setAssociatedData(
          BytesValue.newBuilder().setValue(ByteString.copyFrom(associatedData.get())).build());
    }
    return keysetStub.writeEncrypted(requestBuilder.build());
  }

  @Test
  public void generateEncryptDecryptKeyset() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("AES128_GCM"));

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    KeysetGenerateResponse masterKeysetResponse = generateKeyset(keysetStub, template);
    assertThat(masterKeysetResponse.getErr()).isEmpty();
    byte[] masterKeyset = masterKeysetResponse.getKeyset().toByteArray();

    KeysetWriteEncryptedResponse writeResponse =
        keysetWriteEncrypted(
            keysetStub, keyset, masterKeyset, /*associatedData=*/ Optional.empty());
    assertThat(writeResponse.getErr()).isEmpty();
    byte[] encryptedKeyset = writeResponse.getEncryptedKeyset().toByteArray();

    assertThat(encryptedKeyset).isNotEqualTo(keyset);

    KeysetReadEncryptedResponse readResponse =
        keysetReadEncrypted(
            keysetStub, encryptedKeyset, masterKeyset, /*associatedData=*/ Optional.empty());
    assertThat(readResponse.getErr()).isEmpty();
    byte[] output = readResponse.getKeyset().toByteArray();

    assertThat(output).isEqualTo(keyset);

    // Empty associated data should be the same as no associated data.
    KeysetReadEncryptedResponse readResponseWithEmptyAssociatedData =
        keysetReadEncrypted(
            keysetStub,
            encryptedKeyset,
            masterKeyset,
            /*associatedData=*/ Optional.of(new byte[0]));
    assertThat(readResponseWithEmptyAssociatedData.getErr()).isEmpty();
    assertThat(readResponseWithEmptyAssociatedData.getKeyset().toByteArray()).isEqualTo(keyset);

    KeysetReadEncryptedResponse readResponseWithInvalidAssociatedData =
        keysetReadEncrypted(
            keysetStub,
            encryptedKeyset,
            masterKeyset,
            Optional.of("invalidAssociatedData".getBytes(UTF_8)));
    assertThat(readResponseWithInvalidAssociatedData.getErr()).isNotEmpty();
  }

  @Test
  public void generateEncryptDecryptKeysetWithAssociatedData() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("AES128_GCM"));
    byte[] associatedData = "a".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    KeysetGenerateResponse masterKeysetResponse = generateKeyset(keysetStub, template);
    assertThat(masterKeysetResponse.getErr()).isEmpty();
    byte[] masterKeyset = masterKeysetResponse.getKeyset().toByteArray();

    KeysetWriteEncryptedResponse writeResponse =
        keysetWriteEncrypted(keysetStub, keyset, masterKeyset, Optional.of(associatedData));
    assertThat(writeResponse.getErr()).isEmpty();
    byte[] encryptedKeyset = writeResponse.getEncryptedKeyset().toByteArray();

    assertThat(encryptedKeyset).isNotEqualTo(keyset);

    KeysetReadEncryptedResponse readResponse =
        keysetReadEncrypted(keysetStub, encryptedKeyset, masterKeyset, Optional.of(associatedData));
    assertThat(readResponse.getErr()).isEmpty();
    byte[] output = readResponse.getKeyset().toByteArray();

    assertThat(output).isEqualTo(keyset);

    KeysetReadEncryptedResponse readResponseWithInvalidAssociatedData =
        keysetReadEncrypted(
            keysetStub,
            encryptedKeyset,
            masterKeyset,
            Optional.of("invalidAssociatedData".getBytes(UTF_8)));
    assertThat(readResponseWithInvalidAssociatedData.getErr()).isNotEmpty();

    KeysetReadEncryptedResponse readResponseWithoutAssociatedData =
        keysetReadEncrypted(
            keysetStub, encryptedKeyset, masterKeyset, /*associatedData=*/ Optional.empty());
    assertThat(readResponseWithoutAssociatedData.getErr()).isNotEmpty();
  }

  @Test
  public void generateEncryptDecryptKeysetWithEmptyAssociatedData() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("AES128_GCM"));
    byte[] emptyAssociatedData = new byte[0];

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    KeysetGenerateResponse masterKeysetResponse = generateKeyset(keysetStub, template);
    assertThat(masterKeysetResponse.getErr()).isEmpty();
    byte[] masterKeyset = masterKeysetResponse.getKeyset().toByteArray();

    KeysetWriteEncryptedResponse writeResponse =
        keysetWriteEncrypted(keysetStub, keyset, masterKeyset, Optional.of(emptyAssociatedData));
    assertThat(writeResponse.getErr()).isEmpty();
    byte[] encryptedKeyset = writeResponse.getEncryptedKeyset().toByteArray();

    assertThat(encryptedKeyset).isNotEqualTo(keyset);

    KeysetReadEncryptedResponse readResponse =
        keysetReadEncrypted(
            keysetStub, encryptedKeyset, masterKeyset, Optional.of(emptyAssociatedData));
    assertThat(readResponse.getErr()).isEmpty();
    byte[] output = readResponse.getKeyset().toByteArray();
    assertThat(output).isEqualTo(keyset);

    KeysetReadEncryptedResponse readResponseWithoutAssociatedData =
        keysetReadEncrypted(keysetStub, encryptedKeyset, masterKeyset, Optional.empty());
    assertThat(readResponseWithoutAssociatedData.getErr()).isEmpty();
    assertThat(readResponseWithoutAssociatedData.getKeyset().toByteArray()).isEqualTo(keyset);
  }

  @Test
  public void encryptDecryptInvalidKeyset_fails() throws Exception {
    byte[] invalidData = "invalid".getBytes(UTF_8);
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("AES128_GCM"));

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    KeysetGenerateResponse masterKeysetResponse = generateKeyset(keysetStub, template);
    assertThat(masterKeysetResponse.getErr()).isEmpty();
    byte[] masterKeyset = masterKeysetResponse.getKeyset().toByteArray();

    KeysetWriteEncryptedResponse writeResponse1 =
        keysetWriteEncrypted(keysetStub, keyset, invalidData, /*associatedData=*/ Optional.empty());
    assertThat(writeResponse1.getErr()).isNotEmpty();

    KeysetWriteEncryptedResponse writeResponse2 =
        keysetWriteEncrypted(
            keysetStub, invalidData, masterKeyset, /*associatedData=*/ Optional.empty());
    assertThat(writeResponse2.getErr()).isNotEmpty();

    KeysetReadEncryptedResponse readResponse1 =
        keysetReadEncrypted(keysetStub, keyset, invalidData, /*associatedData=*/ Optional.empty());
    assertThat(readResponse1.getErr()).isNotEmpty();

    KeysetReadEncryptedResponse readResponse2 =
        keysetReadEncrypted(
            keysetStub, invalidData, masterKeyset, /*associatedData=*/ Optional.empty());
    assertThat(readResponse2.getErr()).isNotEmpty();
  }

  // TODO(juerg): Add tests for KEYSET_WRITER_JSON.

  @Test
  public void aeadCreateKeyset_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("AES128_GCM"));
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    CreationResponse response =
        aeadStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(keysetResponse.getKeyset())
                        .build())
                .build());
    assertThat(response.getErr()).isEmpty();
  }

  @Test
  public void aeadCreateKeyset_fails() throws Exception {
    CreationResponse response =
        aeadStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                        .build())
                .build());
    assertThat(response.getErr()).isNotEmpty();
  }

  private static AeadEncryptResponse aeadEncrypt(
      AeadGrpc.AeadBlockingStub aeadStub, byte[] keyset, byte[] plaintext, byte[] associatedData) {
    AeadEncryptRequest encRequest =
        AeadEncryptRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .setPlaintext(ByteString.copyFrom(plaintext))
            .setAssociatedData(ByteString.copyFrom(associatedData))
            .build();
    return aeadStub.encrypt(encRequest);
  }

  private static AeadDecryptResponse aeadDecrypt(
      AeadGrpc.AeadBlockingStub aeadStub, byte[] keyset, byte[] ciphertext, byte[] associatedData) {
    AeadDecryptRequest decRequest =
        AeadDecryptRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .setAssociatedData(ByteString.copyFrom(associatedData))
            .build();
    return aeadStub.decrypt(decRequest);
  }

  @Test
  public void aeadGenerateEncryptDecrypt_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("AES128_GCM"));
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "generate_encrypt_decrypt".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    AeadEncryptResponse encResponse = aeadEncrypt(aeadStub, keyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    AeadDecryptResponse decResponse = aeadDecrypt(aeadStub, keyset, ciphertext, associatedData);
    assertThat(decResponse.getErr()).isEmpty();
    byte[] output = decResponse.getPlaintext().toByteArray();

    assertThat(output).isEqualTo(plaintext);
  }

  @Test
  public void generateKeyset_failsOnBadTemplate() throws Exception {
    byte[] badTemplate = "bad template".getBytes(UTF_8);
    KeysetGenerateResponse genResponse = generateKeyset(keysetStub, badTemplate);
    assertThat(genResponse.getErr()).isNotEmpty();
  }

  @Test
  public void aeadDecrypt_failsOnBadCiphertext() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(KeyTemplates.get("AES128_GCM"));
    byte[] badCiphertext = "bad ciphertext".getBytes(UTF_8);
    byte[] associatedData = "aead_decrypt_fails_on_bad_ciphertext".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    AeadDecryptResponse decResponse = aeadDecrypt(aeadStub, keyset, badCiphertext, associatedData);
    assertThat(decResponse.getErr()).isNotEmpty();
  }

  @Test
  public void deterministicAeadCreateKeyset_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(AesSivKeyManager.aes256SivTemplate());
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    CreationResponse response =
        daeadStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder().setSerializedKeyset(keysetResponse.getKeyset()))
                .build());
    assertThat(response.getErr()).isEmpty();
  }

  @Test
  public void deterministicAeadCreateKeyset_fails() throws Exception {
    CreationResponse response =
        daeadStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(ByteString.copyFrom(new byte[] {(byte) 0x80})))
                .build());
    assertThat(response.getErr()).isNotEmpty();
  }

  private static DeterministicAeadEncryptResponse daeadEncrypt(
      DeterministicAeadGrpc.DeterministicAeadBlockingStub daeadStub,
      byte[] keyset,
      byte[] plaintext,
      byte[] associatedData) {
    DeterministicAeadEncryptRequest encRequest =
        DeterministicAeadEncryptRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder().setSerializedKeyset(ByteString.copyFrom(keyset)))
            .setPlaintext(ByteString.copyFrom(plaintext))
            .setAssociatedData(ByteString.copyFrom(associatedData))
            .build();
    return daeadStub.encryptDeterministically(encRequest);
  }

  private static DeterministicAeadDecryptResponse daeadDecrypt(
      DeterministicAeadGrpc.DeterministicAeadBlockingStub daeadStub,
      byte[] keyset,
      byte[] ciphertext,
      byte[] associatedData) {
    DeterministicAeadDecryptRequest decRequest =
        DeterministicAeadDecryptRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .setAssociatedData(ByteString.copyFrom(associatedData))
            .build();
    return daeadStub.decryptDeterministically(decRequest);
  }

  @Test
  public void daeadGenerateEncryptDecryptDeterministically_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(AesSivKeyManager.aes256SivTemplate());
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "generate_encrypt_decrypt".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    DeterministicAeadEncryptResponse encResponse =
        daeadEncrypt(daeadStub, keyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    DeterministicAeadDecryptResponse decResponse =
        daeadDecrypt(daeadStub, keyset, ciphertext, associatedData);
    assertThat(decResponse.getErr()).isEmpty();
    byte[] output = decResponse.getPlaintext().toByteArray();

    assertThat(output).isEqualTo(plaintext);
  }

  @Test
  public void daeadEncryptDeterministically_failsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "aead_encrypt_fails_on_bad_keyset".getBytes(UTF_8);
    assertThrows(
        StatusRuntimeException.class,
        () -> daeadEncrypt(daeadStub, badKeyset, plaintext, associatedData));
  }

  @Test
  public void daeadDecryptDeterministically_failsOnBadCiphertext() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(AesSivKeyManager.aes256SivTemplate());
    byte[] badCiphertext = "bad ciphertext".getBytes(UTF_8);
    byte[] associatedData = "aead_decrypt_fails_on_bad_ciphertext".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    DeterministicAeadDecryptResponse decResponse =
        daeadDecrypt(daeadStub, keyset, badCiphertext, associatedData);
    assertThat(decResponse.getErr()).isNotEmpty();
  }

  @Test
  public void daeadDecryptDeterministically_failsOnBadKeyset() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(AesSivKeyManager.aes256SivTemplate());
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "generate_encrypt_decrypt".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    DeterministicAeadEncryptResponse encResponse =
        daeadEncrypt(daeadStub, keyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    assertThrows(
        StatusRuntimeException.class,
        () -> daeadDecrypt(daeadStub, badKeyset, ciphertext, associatedData));
  }

  @Test
  public void streamingAeadCreateKeyset_success() throws Exception {
    byte[] template =
        KeyTemplateProtoConverter.toByteArray(
            AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate());
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    CreationResponse response =
        streamingAeadStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(keysetResponse.getKeyset())
                        .build())
                .build());
    assertThat(response.getErr()).isEmpty();
  }

  @Test
  public void streamingAeadCreateKeyset_fails() throws Exception {
    CreationResponse response =
        streamingAeadStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                        .build())
                .build());
    assertThat(response.getErr()).isNotEmpty();
  }

  private static StreamingAeadEncryptResponse streamingAeadEncrypt(
      StreamingAeadGrpc.StreamingAeadBlockingStub streamingAeadStub,
      byte[] keyset,
      byte[] plaintext,
      byte[] associatedData) {
    StreamingAeadEncryptRequest encRequest =
        StreamingAeadEncryptRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .setPlaintext(ByteString.copyFrom(plaintext))
            .setAssociatedData(ByteString.copyFrom(associatedData))
            .build();
    return streamingAeadStub.encrypt(encRequest);
  }

  private static StreamingAeadDecryptResponse streamingAeadDecrypt(
      StreamingAeadGrpc.StreamingAeadBlockingStub streamingAeadStub,
      byte[] keyset,
      byte[] ciphertext,
      byte[] associatedData) {
    StreamingAeadDecryptRequest decRequest =
        StreamingAeadDecryptRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .setAssociatedData(ByteString.copyFrom(associatedData))
            .build();
    return streamingAeadStub.decrypt(decRequest);
  }

  @Test
  public void streamingAeadGenerateEncryptDecrypt_success() throws Exception {
    byte[] template =
        KeyTemplateProtoConverter.toByteArray(
            AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate());
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "generate_encrypt_decrypt".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    StreamingAeadEncryptResponse encResponse =
        streamingAeadEncrypt(streamingAeadStub, keyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    StreamingAeadDecryptResponse decResponse =
        streamingAeadDecrypt(streamingAeadStub, keyset, ciphertext, associatedData);
    assertThat(decResponse.getErr()).isEmpty();
    byte[] output = decResponse.getPlaintext().toByteArray();

    assertThat(output).isEqualTo(plaintext);
  }

  @Test
  public void streamingAeadEncrypt_failsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "streamingAead_encrypt_fails_on_bad_keyset".getBytes(UTF_8);
    StreamingAeadEncryptResponse encResponse =
        streamingAeadEncrypt(streamingAeadStub, badKeyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isNotEmpty();
  }

  @Test
  public void streamingAeadDecrypt_failsOnBadCiphertext() throws Exception {
    byte[] template =
        KeyTemplateProtoConverter.toByteArray(
            AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate());
    byte[] badCiphertext = "bad ciphertext".getBytes(UTF_8);
    byte[] associatedData = "streamingAead_decrypt_fails_on_bad_ciphertext".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    StreamingAeadDecryptResponse decResponse =
        streamingAeadDecrypt(streamingAeadStub, keyset, badCiphertext, associatedData);
    assertThat(decResponse.getErr()).isNotEmpty();
  }

  @Test
  public void streamingAeadDecrypt_failsOnBadKeyset() throws Exception {
    byte[] template =
        KeyTemplateProtoConverter.toByteArray(
            AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate());
    byte[] plaintext = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    byte[] associatedData = "generate_encrypt_decrypt".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    StreamingAeadEncryptResponse encResponse =
        streamingAeadEncrypt(streamingAeadStub, keyset, plaintext, associatedData);
    assertThat(encResponse.getErr()).isEmpty();
    byte[] ciphertext = encResponse.getCiphertext().toByteArray();

    byte[] badKeyset = "bad keyset".getBytes(UTF_8);

    StreamingAeadDecryptResponse decResponse =
        streamingAeadDecrypt(streamingAeadStub, badKeyset, ciphertext, associatedData);
    assertThat(decResponse.getErr()).isNotEmpty();
  }

  @Test
  public void macCreateKeyset_success() throws Exception {
    byte[] template =
        KeyTemplateProtoConverter.toByteArray(HmacKeyManager.hmacSha256HalfDigestTemplate());
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    CreationResponse response =
        macStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(keysetResponse.getKeyset())
                        .build())
                .build());
    assertThat(response.getErr()).isEmpty();
  }

  @Test
  public void macCreateKeyset_fails() throws Exception {
    CreationResponse response =
        macStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                        .build())
                .build());
    assertThat(response.getErr()).isNotEmpty();
  }

  private static ComputeMacResponse computeMac(
      MacGrpc.MacBlockingStub macStub, byte[] keyset, byte[] data) {
    ComputeMacRequest request =
        ComputeMacRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .setData(ByteString.copyFrom(data))
            .build();
    return macStub.computeMac(request);
  }

  private static VerifyMacResponse verifyMac(
      MacGrpc.MacBlockingStub macStub, byte[] keyset, byte[] macValue, byte[] data) {
    VerifyMacRequest request =
        VerifyMacRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .setMacValue(ByteString.copyFrom(macValue))
            .setData(ByteString.copyFrom(data))
            .build();
    return macStub.verifyMac(request);
  }

  @Test
  public void computeVerifyMac_success() throws Exception {
    byte[] template =
        KeyTemplateProtoConverter.toByteArray(HmacKeyManager.hmacSha256HalfDigestTemplate());
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    ComputeMacResponse compResponse = computeMac(macStub, keyset, data);
    assertThat(compResponse.getErr()).isEmpty();
    byte[] macValue = compResponse.getMacValue().toByteArray();

    VerifyMacResponse verifyResponse = verifyMac(macStub, keyset, macValue, data);
    assertThat(verifyResponse.getErr()).isEmpty();
  }

  @Test
  public void computeMac_failsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);

    ComputeMacResponse compResponse = computeMac(macStub, badKeyset, data);
    assertThat(compResponse.getErr()).isNotEmpty();
  }

  @Test
  public void verifyMac_failsOnBadMacValue() throws Exception {
    byte[] template =
        KeyTemplateProtoConverter.toByteArray(HmacKeyManager.hmacSha256HalfDigestTemplate());
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    VerifyMacResponse verifyResponse =
        verifyMac(macStub, keyset, "bad mac_value".getBytes(UTF_8), data);
    assertThat(verifyResponse.getErr()).isNotEmpty();
  }

  @Test
  public void verifyMac_failsOnBadKeyset() throws Exception {
    byte[] template =
        KeyTemplateProtoConverter.toByteArray(HmacKeyManager.hmacSha256HalfDigestTemplate());
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    ComputeMacResponse compResponse = computeMac(macStub, keyset, data);
    assertThat(compResponse.getErr()).isEmpty();
    byte[] macValue = compResponse.getMacValue().toByteArray();

    byte[] badKeyset = "bad keyset".getBytes(UTF_8);
    VerifyMacResponse verifyResponse = verifyMac(macStub, badKeyset, macValue, data);
    assertThat(verifyResponse.getErr()).isNotEmpty();
  }

  @Test
  public void prfSetCreateKeyset_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(HmacPrfKeyManager.hmacSha256Template());
    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    CreationResponse response =
        prfSetStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(keysetResponse.getKeyset())
                        .build())
                .build());
    assertThat(response.getErr()).isEmpty();
  }

  @Test
  public void prfSetCreateKeyset_fails() throws Exception {
    CreationResponse response =
        prfSetStub.create(
            CreationRequest.newBuilder()
                .setAnnotatedKeyset(
                    AnnotatedKeyset.newBuilder()
                        .setSerializedKeyset(ByteString.copyFrom(new byte[] {(byte) 0x80}))
                        .build())
                .build());
    assertThat(response.getErr()).isNotEmpty();
  }

  private static PrfSetKeyIdsResponse keyIds(
      PrfSetGrpc.PrfSetBlockingStub prfSetStub, byte[] keyset) {
    PrfSetKeyIdsRequest request =
        PrfSetKeyIdsRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .build();
    return prfSetStub.keyIds(request);
  }

  private static PrfSetComputeResponse computePrf(
      PrfSetGrpc.PrfSetBlockingStub prfSetStub,
      byte[] keyset,
      int keyId,
      byte[] inputData,
      int outputLength) {
    PrfSetComputeRequest request =
        PrfSetComputeRequest.newBuilder()
            .setAnnotatedKeyset(
                AnnotatedKeyset.newBuilder()
                    .setSerializedKeyset(ByteString.copyFrom(keyset))
                    .build())
            .setKeyId(keyId)
            .setInputData(ByteString.copyFrom(inputData))
            .setOutputLength(outputLength)
            .build();
    return prfSetStub.compute(request);
  }

  @Test
  public void computePrf_success() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        HmacPrfKeyManager.hmacSha256Template());
    byte[] inputData = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    int outputLength = 15;

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    PrfSetKeyIdsResponse keyIdsResponse = keyIds(prfSetStub, keyset);
    assertThat(keyIdsResponse.getErr()).isEmpty();
    int primaryKeyId = keyIdsResponse.getOutput().getPrimaryKeyId();

    PrfSetComputeResponse computeResponse = computePrf(
        prfSetStub, keyset, primaryKeyId, inputData, outputLength);
    assertThat(computeResponse.getErr()).isEmpty();
    assertThat(computeResponse.getOutput().size()).isEqualTo(outputLength);
  }

  @Test
  public void prfKeyIds_failsOnBadKeyset() throws Exception {
    byte[] badKeyset = "bad keyset".getBytes(UTF_8);

    PrfSetKeyIdsResponse keyIdsResponse = keyIds(prfSetStub, badKeyset);
    assertThat(keyIdsResponse.getErr()).isNotEmpty();
  }

  @Test
  public void computePrf_failsOnUnknownKeyId() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        HmacPrfKeyManager.hmacSha256Template());
    byte[] inputData = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    int outputLength = 15;
    int badKeyId = 123456789;

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    PrfSetComputeResponse computeResponse = computePrf(
        prfSetStub, keyset, badKeyId, inputData, outputLength);
    assertThat(computeResponse.getErr()).isNotEmpty();
  }

  @Test
  public void computePrf_failsOnBadOutputLength() throws Exception {
    byte[] template = KeyTemplateProtoConverter.toByteArray(
        HmacPrfKeyManager.hmacSha256Template());
    byte[] inputData = "The quick brown fox jumps over the lazy dog".getBytes(UTF_8);
    int outputLength = 12345;

    KeysetGenerateResponse keysetResponse = generateKeyset(keysetStub, template);
    assertThat(keysetResponse.getErr()).isEmpty();
    byte[] keyset = keysetResponse.getKeyset().toByteArray();

    PrfSetKeyIdsResponse keyIdsResponse = keyIds(prfSetStub, keyset);
    assertThat(keyIdsResponse.getErr()).isEmpty();
    int primaryKeyId = keyIdsResponse.getOutput().getPrimaryKeyId();

    PrfSetComputeResponse computeResponse = computePrf(
        prfSetStub, keyset, primaryKeyId, inputData, outputLength);
    assertThat(computeResponse.getErr()).isNotEmpty();
  }

  @Test
  public void getServerInfo_success() throws Exception {
    ServerInfoResponse response =
        metadataStub.getServerInfo(ServerInfoRequest.getDefaultInstance());
    assertThat(response.getLanguage()).isEqualTo("java");
    assertThat(response.getTinkVersion()).isNotEmpty();
  }
}
