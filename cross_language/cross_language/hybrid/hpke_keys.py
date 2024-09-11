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
from typing import Iterator, Tuple

from tink.proto import hpke_pb2
from tink.proto import tink_pb2
from cross_language import test_key


_PRIVATE_TYPE_URL = 'type.googleapis.com/google.crypto.tink.HpkePrivateKey'
_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.HpkePublicKey'


# TestVector from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
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


# TestVector from Java Tink implementation
def _basic_p384_key() -> hpke_pb2.HpkePrivateKey:
  return hpke_pb2.HpkePrivateKey(
      version=0,
      public_key=hpke_pb2.HpkePublicKey(
          version=0,
          params=hpke_pb2.HpkeParams(
              kem=hpke_pb2.DHKEM_P384_HKDF_SHA384,
              kdf=hpke_pb2.HKDF_SHA384,
              aead=hpke_pb2.AES_128_GCM,
          ),
          public_key=binascii.unhexlify(
              '049d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c732aa49bc4a38f467edb842481a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a0b2c990ae92b62d6c75180ba'
          ),
      ),
      private_key=binascii.unhexlify(
          '670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f60a27c94caac46bdeeb79897a3ed9'
      ),
  )


# TestVector from Java Tink implementation
def _basic_p521_key() -> hpke_pb2.HpkePrivateKey:
  return hpke_pb2.HpkePrivateKey(
      version=0,
      public_key=hpke_pb2.HpkePublicKey(
          version=0,
          params=hpke_pb2.HpkeParams(
              kem=hpke_pb2.DHKEM_P521_HKDF_SHA512,
              kdf=hpke_pb2.HKDF_SHA512,
              aead=hpke_pb2.AES_128_GCM,
          ),
          public_key=binascii.unhexlify(
              '0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64'
          ),
      ),
      private_key=binascii.unhexlify(
          '01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847'
      ),
  )


def _nist_curve_proto_keys() -> (
    Iterator[Tuple[str, bool, hpke_pb2.HpkePrivateKey]]
):
  """Returns proto keys which use NIST curves."""

  yield('basic_p256_key', True, _basic_p256_key())
  yield('basic_p384_key', True, _basic_p384_key())
  yield('basic_p521_key', True, _basic_p521_key())

  key = _basic_p384_key()
  key.public_key.params.kem = hpke_pb2.DHKEM_P256_HKDF_SHA256
  yield('P256 key with P384 point (invalid)', False, key)

  key = _basic_p521_key()
  key.public_key.params.kem = hpke_pb2.DHKEM_P384_HKDF_SHA384
  yield('P384 key with P521 point (invalid)', False, key)

  key = _basic_p256_key()
  key.public_key.params.kem = hpke_pb2.DHKEM_P521_HKDF_SHA512
  yield('P521 key with P256 point (invalid)', False, key)

  key = _basic_p256_key()
  key.public_key.params.kdf = hpke_pb2.HKDF_SHA512
  yield('P256 key with SHA512', True, key)

  key = _basic_p384_key()
  key.public_key.params.kdf = hpke_pb2.HKDF_SHA256
  yield('P384 key with SHA256', True, key)

  key = _basic_p521_key()
  key.public_key.params.kdf = hpke_pb2.HKDF_SHA384
  yield('P521 key with SHA384', True, key)

  key = _basic_p521_key()
  key.public_key.params.kdf = hpke_pb2.KDF_UNKNOWN
  yield('P521 key with KDF_UNKNOWN (invalid)', False, key)


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


def _wrong_version_keys() -> (
    Iterator[Tuple[str, hpke_pb2.HpkePrivateKey]]
):
  """Yields private keys where not both versions are 0."""

  key = _basic_p256_key()
  key.version = 1
  yield ('PrivateKey Version 1', key)

  key = _basic_p256_key()
  key.public_key.version = 1
  yield ('PublicKey Version 1', key)

  key = _basic_p256_key()
  key.version = 1
  key.public_key.version = 1
  yield ('PrivateKey And PublicKey Version 1', key)


def hpke_private_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HPKE."""

  for (name, valid, proto_key) in _nist_curve_proto_keys():
    if name == 'basic_p256_key':
      tags = ['b/361841214']
    else:
      tags = ['b/235861932']
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=proto_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=valid,
        tags=tags,
    )

  yield test_key.TestKey(
      test_name='basic x25519 key',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=_basic_x25519_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=True,
  )

  for name, wrong_version_key in _wrong_version_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=wrong_version_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=False,
    )


def hpke_public_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HPKE."""

  for (name, valid, proto_key) in _nist_curve_proto_keys():
    if name == 'basic_p256_key':
      tags = ['b/361841214']
    else:
      tags = ['b/235861932']
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=proto_key.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        valid=valid,
        tags=tags,
    )

  yield test_key.TestKey(
      test_name='basic x25519 key',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=_basic_x25519_key().public_key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      valid=True,
  )
