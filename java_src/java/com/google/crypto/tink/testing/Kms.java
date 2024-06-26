// Copyright 2024 Google LLC
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

import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.integration.awskms.AwsKmsClient;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import com.google.crypto.tink.integration.hcvault.HcVaultClient;
import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import java.security.GeneralSecurityException;

/** Registers KMS clients. */
final class Kms {

  // TODO(juerg): Mark parameters nullable.

  private static GcpKmsClient getGcpKmsClient(String uri, String credentialsPath)
      throws GeneralSecurityException {
    GcpKmsClient client = (uri == null) ? new GcpKmsClient() : new GcpKmsClient(uri);
    if (credentialsPath != null) {
      client.withCredentials(credentialsPath);
    } else {
      client.withDefaultCredentials();
    }
    return client;
  }

  private static AwsKmsClient getAwsKmsClient(String uri, String credentialsPath)
      throws GeneralSecurityException {
    AwsKmsClient client = (uri == null) ? new AwsKmsClient() : new AwsKmsClient(uri);
    if (credentialsPath != null) {
      client.withCredentials(credentialsPath);
    } else {
      client.withDefaultCredentials();
    }
    return client;
  }

  private static KmsClient getHcVaultKmsClient(String authToken) throws GeneralSecurityException {
    if (authToken == null) {
      authToken = "";
    }
    try {
      VaultConfig config =
          new VaultConfig()
              .address("https://127.0.0.1:8200")
              .token(authToken)
              .readTimeout(30)
              .openTimeout(30)
              .engineVersion(1)
              .sslConfig(new SslConfig().verify(false).build()) // DO NOT DO THIS IN PRODUCTION
              .build();
      Logical hcVault = new Vault(config).logical();
      return HcVaultClient.create(hcVault);
    } catch (VaultException e) {
      throw new GeneralSecurityException("failed to create client", e);
    }
  }

  public static void register(
      String gcpKeyUri,
      String gcpCredentialsPath,
      String awsKeyUri,
      String awsCredentialsPath,
      String hcvaultToken)
      throws GeneralSecurityException {
    System.out.println("Registering GCP KMS client");
    KmsClients.add(getGcpKmsClient(gcpKeyUri, gcpCredentialsPath));

    System.out.println("Registering AWS KMS client");
    KmsClients.add(getAwsKmsClient(awsKeyUri, awsCredentialsPath));

    System.out.println("Registering HC Vault KMS client");
    KmsClients.add(getHcVaultKmsClient(hcvaultToken));

    System.out.println("Registering Fake KMS client");
    KmsClients.add(new FakeKmsClient());
  }

  private Kms() {}
}
