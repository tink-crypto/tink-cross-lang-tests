// Copyright 2023 Google LLC
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

// Package kms registers all KMS clients
package kms

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/url"

	"github.com/hashicorp/vault/api"

	"flag"
	"google.golang.org/api/option"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go-awskms/v2/integration/awskms"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go-hcvault/v2/integration/hcvault"
	"github.com/tink-crypto/tink-go/v2/testing/fakekms"
)

var (
	gcpCredFilePath     = flag.String("gcp_credentials_path", "", "Google Cloud KMS credentials path")
	gcpKeyURI           = flag.String("gcp_key_uri", "", "Google Cloud KMS key URI of the form: gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*.")
	awsCredFilePath     = flag.String("aws_credentials_path", "", "AWS KMS credentials path")
	awsKeyURI           = flag.String("aws_key_uri", "", "AWS KMS key URI of the form: aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>.")
	hcvaultKeyURIPrefix = flag.String("hcvault_key_uri_prefix", "", "HC Vault key URI prefix of the form: hcvault://example.com:8200/key/path")
	hcvaultToken        = flag.String("hcvault_token", "", "HC Vault token")
)

// RegisterAll registers all KMS clients.
func RegisterAll() {
	client, err := fakekms.NewClient("fake-kms://")
	if err != nil {
		log.Fatalf("fakekms.NewClient failed: %v", err)
	}
	registry.RegisterKMSClient(client)

	gcpClient, err := gcpkms.NewClientWithOptions(context.Background(), *gcpKeyURI, option.WithCredentialsFile(*gcpCredFilePath))
	if err != nil {
		log.Fatalf("gcpkms.NewClientWithOptions failed: %v", err)
	}
	registry.RegisterKMSClient(gcpClient)

	awsClient, err := awskms.NewClientWithOptions(*awsKeyURI, awskms.WithCredentialPath(*awsCredFilePath))
	if err != nil {
		log.Fatalf("awskms.NewClientWithOptions failed: %v", err)
	}
	registry.RegisterKMSClient(awsClient)

	vaultClient, err := newVaultClient(
		*hcvaultKeyURIPrefix,
		// Using InsecureSkipVerify is fine here, since this is just a test running locally.
		&tls.Config{InsecureSkipVerify: true}, // NOLINT
		*hcvaultToken)
	if err != nil {
		log.Fatalf("hcvault.NewClient failed: %v", err)
	}
	registry.RegisterKMSClient(vaultClient)
}

func newVaultClient(uriPrefix string, tlsCfg *tls.Config, token string) (registry.KMSClient, error) {
	httpClient := api.DefaultConfig().HttpClient
	transport := httpClient.Transport.(*http.Transport)
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	} else {
		tlsCfg = tlsCfg.Clone()
	}
	transport.TLSClientConfig = tlsCfg

	vURL, err := url.Parse(uriPrefix)
	if err != nil {
		return nil, err
	}
	cfg := &api.Config{
		Address:    "https://" + vURL.Host,
		HttpClient: httpClient,
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return hcvault.NewClientWithAEADOptions(uriPrefix, client.Logical())
}
