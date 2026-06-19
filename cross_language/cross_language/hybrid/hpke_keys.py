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


def _basic_x_wing_key() -> hpke_pb2.HpkePrivateKey:
  return hpke_pb2.HpkePrivateKey(
      version=0,
      public_key=hpke_pb2.HpkePublicKey(
          version=0,
          params=hpke_pb2.HpkeParams(
              kem=hpke_pb2.X_WING,
              kdf=hpke_pb2.HKDF_SHA256,
              aead=hpke_pb2.AES_128_GCM,
          ),
          public_key=binascii.unhexlify(
              'e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d'
              'a5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b'
              '2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a52534'
              '01bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced4076992361'
              '0034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c'
              '1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da06'
              '3bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2ae'
              'a10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e'
              'ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40'
              'b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c'
              '1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362'
              '543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564'
              '955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17e'
              'd55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af'
              '829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519'
              '317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4'
              '87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be'
              '3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587'
              'ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584'
              'fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c'
              '8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc09'
              '0544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c95'
              '2151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae406'
              '5ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5'
              '7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e3173'
              '46e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573'
              'cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d1369'
              '8a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c'
              '1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44'
              'd3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da96'
              '9e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611'
              'd0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734'
              '9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06'
              'eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534'
          ),
      ),
      private_key=binascii.unhexlify(
          '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'
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

  yield test_key.TestKey(
      test_name='basic x-wing key',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=_basic_x_wing_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=True,
      tags=['x_wing'],
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

  yield test_key.TestKey(
      test_name='basic x-wing key',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=_basic_x_wing_key().public_key.SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      valid=True,
      tags=['x_wing'],
  )
