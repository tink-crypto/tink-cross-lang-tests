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

"""Test keys for HPKE."""

import binascii
from typing import Iterator

from tink.proto import hpke_pb2
from tink.proto import tink_pb2
from cross_language import test_key


_PRIVATE_TYPE_URL = 'type.googleapis.com/google.crypto.tink.HpkePrivateKey'
_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.HpkePublicKey'


def _basic_p256_key() -> hpke_pb2.HpkePrivateKey:
  return hpke_pb2.HpkePrivateKey(
      version=0,
      public_key=hpke_pb2.HpkePublicKey(
          version=0,
          params=hpke_pb2.HpkeParams(
              kem=hpke_pb2.DHKEM_P256_HKDF_SHA256,
              kdf=hpke_pb2.HKDF_SHA256,
              aead=hpke_pb2.AES_128_GCM,
          ),
          public_key=binascii.unhexlify(
              '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'
          ),
      ),
      private_key=binascii.unhexlify(
          '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb'
      ),
  )


def _basic_x25519_key() -> hpke_pb2.HpkePrivateKey:
  return hpke_pb2.HpkePrivateKey(
      version=0,
      public_key=hpke_pb2.HpkePublicKey(
          version=0,
          params=hpke_pb2.HpkeParams(
              kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
              kdf=hpke_pb2.HKDF_SHA256,
              aead=hpke_pb2.AES_128_GCM,
          ),
          public_key=binascii.unhexlify(
              '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431'
          ),
      ),
      private_key=binascii.unhexlify(
          '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736'
      ),
  )


def hpke_private_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HPKE."""

  yield test_key.TestKey(
      test_name='basic p256 key',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=_basic_p256_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=True,
      tags=['b/235861932'],
  )

  yield test_key.TestKey(
      test_name='basic x25519 key',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=_basic_x25519_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=True,
  )


def hpke_public_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HPKE."""

  yield test_key.TestKey(
      test_name='basic p256 public key',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=_basic_p256_key().public_key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      valid=True,
      tags=['b/235861932'],
  )

  yield test_key.TestKey(
      test_name='basic x25519 key',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=_basic_x25519_key().public_key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      valid=True,
  )
