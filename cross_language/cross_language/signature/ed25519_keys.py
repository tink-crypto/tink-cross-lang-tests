# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test keys for Ed25519."""

import binascii
from typing import Iterator, Tuple

from tink.proto import ed25519_pb2
from tink.proto import tink_pb2
from cross_language import test_key


_PRIVATE_TYPE_URL = 'type.googleapis.com/google.crypto.tink.Ed25519PrivateKey'
_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.Ed25519PublicKey'


def _basic_ed25519_key() -> ed25519_pb2.Ed25519PrivateKey:
  return ed25519_pb2.Ed25519PrivateKey(
      version=0,
      key_value=binascii.unhexlify(
          '9cac7d19aeecc563a3dff7bcae0fbbbc28087b986c49a3463077dd5281437e81'
      ),
      public_key=ed25519_pb2.Ed25519PublicKey(
          version=0,
          key_value=binascii.unhexlify(
              'ea42941a6dc801484390b2955bc7376d172eeb72640a54e5b50c95efa2fc6ad8'
          ),
      ),
  )


def _wrong_version_keys() -> (
    Iterator[Tuple[str, ed25519_pb2.Ed25519PrivateKey]]
):
  """Yields private keys where not both versions are 0."""

  key = _basic_ed25519_key()
  key.version = 1
  yield ('PrivateKey Version 1', key)

  key = _basic_ed25519_key()
  key.public_key.version = 1
  yield ('PublicKey Version 1', key)

  key = _basic_ed25519_key()
  key.version = 1
  key.public_key.version = 1
  yield ('PrivateKey And PublicKey Version 1', key)


def ed25519_private_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for Ed25519."""
  yield test_key.TestKey(
      test_name='Basic Key, TINK',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=_basic_ed25519_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='Basic Key, RAW',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=_basic_ed25519_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='Basic Key, CRUNCHY',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=_basic_ed25519_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='Basic Key, LEGACY',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=_basic_ed25519_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      valid=True,
  )
  key = _basic_ed25519_key()
  # Some bytes are replaced with "ff"
  key.public_key.key_value = binascii.unhexlify(
      'ff42ff1a6dcff1484390b2955bc7376d172eeb72640a54e5b50c95efa2fc6ad8'
  )
  yield test_key.TestKey(
      test_name='Inconsistent public key value',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=False,
      tags=['b/315954817'],
  )
  for name, wrong_version_key in _wrong_version_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=wrong_version_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=False,
    )


def ed25519_public_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for Ed25519."""
  yield test_key.TestKey(
      test_name='Basic Key, TINK',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=_basic_ed25519_key().public_key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='Basic Key, RAW',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=_basic_ed25519_key().public_key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='Basic Key, CRUNCHY',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=_basic_ed25519_key().public_key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='Basic Key, LEGACY',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=_basic_ed25519_key().public_key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      valid=True,
  )
