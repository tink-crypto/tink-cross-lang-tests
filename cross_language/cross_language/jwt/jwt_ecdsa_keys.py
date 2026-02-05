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

"""Test keys for JWT ECDSA."""

import binascii
from typing import Iterator, Tuple

from tink.proto import jwt_ecdsa_pb2
from tink.proto import tink_pb2
from cross_language import test_key


_PRIVATE_TYPE_URL = 'type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey'
_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey'


def _p256_point_x() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
  )


def _p256_point_y() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'
  )


def _p256_private_value() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'
  )


def _p256_values_short_private_key() -> Tuple[bytes, bytes, bytes]:
  """Returns a private/public keys pair, where the private key is 31 bytes long.

  These values come from the C++ unit test named
  EcdsaPrivateKeyTest.CreatePrivateKeyWithOneTooFewBytes.
  """
  x = binascii.unhexlify(
      '9031a2a43467ed31a8de8e2b28861c0ca5605ff4443c3dbea0bd47ebb65a02ae'
  )
  y = binascii.unhexlify(
      '8d094fc9fa9b328ca3060802045d5c5f6b0a51a432a844a7f0f3dbf9de039f43'
  )

  private_key = binascii.unhexlify(
      '0a11c3c4ed77aa0d6fc34ee0f91d5970ff22619cc2583cf51bc5654ec9400d'
  )
  return (x, y, private_key)


def _p384_point_x() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '009d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c732aa49bc4a38f467edb8424'
  )


def _p384_point_y() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '0081a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a0b2c990ae92b62d6c75180ba'
  )


def _p384_private_value() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f60a27c94caac46bdeeb79897a3ed9'
  )


def _p521_point_x() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4'
  )


def _p521_point_y() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5'
  )


def _p521_private_value() -> bytes:
  """All points are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538'
  )


def _basic_es256_key() -> jwt_ecdsa_pb2.JwtEcdsaPrivateKey:
  return jwt_ecdsa_pb2.JwtEcdsaPrivateKey(
      version=0,
      public_key=jwt_ecdsa_pb2.JwtEcdsaPublicKey(
          algorithm=jwt_ecdsa_pb2.JwtEcdsaAlgorithm.ES256,
          x=_p256_point_x(),
          y=_p256_point_y(),
      ),
      key_value=_p256_private_value(),
  )


def _short_es256_key() -> jwt_ecdsa_pb2.JwtEcdsaPrivateKey:
  x, y, private_key = _p256_values_short_private_key()
  return jwt_ecdsa_pb2.JwtEcdsaPrivateKey(
      version=0,
      public_key=jwt_ecdsa_pb2.JwtEcdsaPublicKey(
          algorithm=jwt_ecdsa_pb2.JwtEcdsaAlgorithm.ES256,
          x=x,
          y=y,
      ),
      key_value=private_key,
  )


def _padded_es256_key() -> jwt_ecdsa_pb2.JwtEcdsaPrivateKey:
  x, y, private_key = _p256_values_short_private_key()
  return jwt_ecdsa_pb2.JwtEcdsaPrivateKey(
      version=0,
      public_key=jwt_ecdsa_pb2.JwtEcdsaPublicKey(
          algorithm=jwt_ecdsa_pb2.JwtEcdsaAlgorithm.ES256,
          x=x,
          y=y,
      ),
      key_value=b'\x00' * 3 + private_key,
  )


def _basic_es384_key() -> jwt_ecdsa_pb2.JwtEcdsaPrivateKey:
  return jwt_ecdsa_pb2.JwtEcdsaPrivateKey(
      version=0,
      public_key=jwt_ecdsa_pb2.JwtEcdsaPublicKey(
          algorithm=jwt_ecdsa_pb2.JwtEcdsaAlgorithm.ES384,
          x=_p384_point_x(),
          y=_p384_point_y(),
      ),
      key_value=_p384_private_value(),
  )


def _basic_es512_key() -> jwt_ecdsa_pb2.JwtEcdsaPrivateKey:
  return jwt_ecdsa_pb2.JwtEcdsaPrivateKey(
      version=0,
      public_key=jwt_ecdsa_pb2.JwtEcdsaPublicKey(
          algorithm=jwt_ecdsa_pb2.JwtEcdsaAlgorithm.ES512,
          x=_p521_point_x(),
          y=_p521_point_y(),
      ),
      key_value=_p521_private_value(),
  )


def _proto_keys() -> (
    Iterator[Tuple[str, bool, jwt_ecdsa_pb2.JwtEcdsaPrivateKey]]
):
  """Returns triples (name, validity, proto) for JwtEcdsaPrivateKey."""

  yield ('basic ES256 key', True, _basic_es256_key())
  yield ('short ES256 key', True, _short_es256_key())
  yield ('padded ES256 key', True, _padded_es256_key())
  yield ('basic ES384 key', True, _basic_es384_key())
  yield ('basic ES512 key', True, _basic_es512_key())


def _create_mismatched_keys() -> (
    Iterator[Tuple[str, bool, jwt_ecdsa_pb2.JwtEcdsaPrivateKey]]
):
  """Returns triples (name, validity, proto) with mismatched key values."""
  key = _basic_es512_key()
  key.public_key.algorithm = jwt_ecdsa_pb2.JwtEcdsaAlgorithm.ES256
  yield ('ES256 key with P521 point (invalid)', False, key)

  key = _basic_es512_key()
  key.public_key.algorithm = jwt_ecdsa_pb2.JwtEcdsaAlgorithm.ES384
  yield ('ES384 key with P521 point (invalid)', False, key)

  key = _basic_es256_key()
  key.public_key.algorithm = jwt_ecdsa_pb2.JwtEcdsaAlgorithm.ES512
  yield ('ES512 key with P256 point (invalid)', False, key)


def jwt_ecdsa_private_keys() -> Iterator[test_key.TestKey]:
  """Returns private test keys for Ecdsa."""

  for name, valid, key_proto in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=valid,
    )

  for name, valid, key_proto in _create_mismatched_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=valid,
    )


def jwt_ecdsa_public_keys() -> Iterator[test_key.TestKey]:
  """Returns public test keys for Ecdsa."""

  for name, valid, key_proto in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=key_proto.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        valid=valid,
    )

  for name, valid, key_proto in _create_mismatched_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=key_proto.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        valid=valid,
    )
