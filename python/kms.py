# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""KMS client registrations."""

from absl import flags

import hvac

import tink
from tink import aead
from tink.integration import awskms
from tink.integration import gcpkms
from tink.integration import hcvault


GCP_CREDENTIALS_PATH = flags.DEFINE_string(
    'gcp_credentials_path', '', 'Google Cloud KMS credentials path.')
GCP_KEY_URI = flags.DEFINE_string(
    'gcp_key_uri', '', 'Google Cloud KMS key URL of the form: '
    'gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*.')

AWS_CREDENTIALS_PATH = flags.DEFINE_string('aws_credentials_path', '',
                                           'AWS KMS credentials path.')
AWS_KEY_URI = flags.DEFINE_string(
    'aws_key_uri', '', 'AWS KMS key URL of the form: '
    'aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>.')
HCVAULT_TOKEN = flags.DEFINE_string(
    'hcvault_token', '', 'HC Vault access token.')


class HcVaultKmsClient(tink.KmsClient):
  """KmsClient for HC Vault."""

  def __init__(self, token: str) -> None:
    self._client = hvac.Client(
        url='https://127.0.0.1:8200',
        token=token,
        verify=False)
    self._prefix = 'hcvault://127.0.0.1:8200/'

  def does_support(self, key_uri: str) -> bool:
    return key_uri.startswith(self._prefix)

  def get_aead(self, key_uri: str) -> aead.Aead:
    if not key_uri.startswith(self._prefix):
      raise tink.TinkError('Unknown key_uri.')
    key_path = key_uri[len(self._prefix) :]
    return hcvault.new_aead(key_path, self._client)


def init() -> None:
  """Registers some KMS clients."""
  gcpkms.GcpKmsClient.register_client(
      key_uri=GCP_KEY_URI.value,
      credentials_path=GCP_CREDENTIALS_PATH.value
  )
  awskms.AwsKmsClient.register_client(
      key_uri=AWS_KEY_URI.value,
      credentials_path=AWS_CREDENTIALS_PATH.value
  )
  tink.register_kms_client(HcVaultKmsClient(HCVAULT_TOKEN.value))
