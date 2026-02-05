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

from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import tink_pb2
from cross_language import test_key


_PRIVATE_TYPE_URL = 'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey'
_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.EcdsaPublicKey'


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


def _p256_short_key() -> Tuple[bytes, bytes, bytes]:
  """Return values for a private/public key pair, where the private key is 31 bytes long.

  The values are obtained from the C++ unit test named
  EcdsaProtoSerializationTest.ParsePrivateKeyWithShorterKey.
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


def _basic_p256_key() -> ecdsa_pb2.EcdsaPrivateKey:
  return ecdsa_pb2.EcdsaPrivateKey(
      version=0,
      public_key=ecdsa_pb2.EcdsaPublicKey(
          version=0,
          params=ecdsa_pb2.EcdsaParams(
              hash_type=common_pb2.HashType.SHA256,
              curve=common_pb2.EllipticCurveType.NIST_P256,
              encoding=ecdsa_pb2.EcdsaSignatureEncoding.IEEE_P1363,
          ),
          x=_p256_point_x(),
          y=_p256_point_y(),
      ),
      key_value=_p256_private_value(),
  )


def _short_p256_key() -> ecdsa_pb2.EcdsaPrivateKey:
  x, y, private_key = _p256_short_key()
  return ecdsa_pb2.EcdsaPrivateKey(
      version=0,
      public_key=ecdsa_pb2.EcdsaPublicKey(
          version=0,
          params=ecdsa_pb2.EcdsaParams(
              hash_type=common_pb2.HashType.SHA256,
              curve=common_pb2.EllipticCurveType.NIST_P256,
              encoding=ecdsa_pb2.EcdsaSignatureEncoding.IEEE_P1363,
          ),
          x=x,
          y=y,
      ),
      key_value=private_key,
  )


def _padded_p256_key() -> ecdsa_pb2.EcdsaPrivateKey:
  x, y, private_key = _p256_short_key()
  return ecdsa_pb2.EcdsaPrivateKey(
      version=0,
      public_key=ecdsa_pb2.EcdsaPublicKey(
          version=0,
          params=ecdsa_pb2.EcdsaParams(
              hash_type=common_pb2.HashType.SHA256,
              curve=common_pb2.EllipticCurveType.NIST_P256,
              encoding=ecdsa_pb2.EcdsaSignatureEncoding.IEEE_P1363,
          ),
          x=x,
          y=y,
      ),
      key_value=b'\x00' * 3 + private_key,
  )


def _basic_p384_key() -> ecdsa_pb2.EcdsaPrivateKey:
  return ecdsa_pb2.EcdsaPrivateKey(
      version=0,
      public_key=ecdsa_pb2.EcdsaPublicKey(
          version=0,
          params=ecdsa_pb2.EcdsaParams(
              hash_type=common_pb2.HashType.SHA384,
              curve=common_pb2.EllipticCurveType.NIST_P384,
              encoding=ecdsa_pb2.EcdsaSignatureEncoding.IEEE_P1363,
          ),
          x=_p384_point_x(),
          y=_p384_point_y(),
      ),
      key_value=_p384_private_value(),
  )


def _basic_p521_key() -> ecdsa_pb2.EcdsaPrivateKey:
  return ecdsa_pb2.EcdsaPrivateKey(
      version=0,
      public_key=ecdsa_pb2.EcdsaPublicKey(
          version=0,
          params=ecdsa_pb2.EcdsaParams(
              hash_type=common_pb2.HashType.SHA512,
              curve=common_pb2.EllipticCurveType.NIST_P521,
              encoding=ecdsa_pb2.EcdsaSignatureEncoding.IEEE_P1363,
          ),
          x=_p521_point_x(),
          y=_p521_point_y(),
      ),
      key_value=_p521_private_value(),
  )


def _basic_x25519_key() -> ecdsa_pb2.EcdsaPrivateKey:
  """Returns a 'X25519 key'.

  Tink doesn't support X25519 for ECDSA, but the enum exists. We try our best
  to fake a Tink implementation which thinks X25519 is valid and provide
  something the implementation might interpret as valid.
  """

  # x and key_value are taken from hpke_keys.py.
  return ecdsa_pb2.EcdsaPrivateKey(
      version=0,
      public_key=ecdsa_pb2.EcdsaPublicKey(
          version=0,
          params=ecdsa_pb2.EcdsaParams(
              hash_type=common_pb2.HashType.SHA256,
              curve=common_pb2.EllipticCurveType.CURVE25519,
              encoding=ecdsa_pb2.EcdsaSignatureEncoding.IEEE_P1363,
          ),
          x=binascii.unhexlify(
              '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431'
          ),
      ),
      key_value=binascii.unhexlify(
          '52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736'
      ),
  )


def _wrong_version_keys() -> Iterator[Tuple[str, ecdsa_pb2.EcdsaPrivateKey]]:
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


def _unsupported_hash_function_keys() -> (
    Iterator[Tuple[str, bool, ecdsa_pb2.EcdsaPrivateKey]]
):
  """Returns keys with unsupported hash functions."""

  key_proto = _basic_p256_key()
  key_proto.public_key.params.hash_type = common_pb2.HashType.SHA1
  yield ('SHA1 key (invalid)', False, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.hash_type = common_pb2.HashType.SHA224
  yield ('SHA224 key (invalid)', False, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.hash_type = common_pb2.HashType.UNKNOWN_HASH
  yield ('UNKNOWN_HASH key (invalid)', False, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.hash_type = common_pb2.HashType.SHA384
  yield ('P256 & SHA384 (invalid)', False, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.hash_type = common_pb2.HashType.SHA512
  yield ('P256 & SHA512 (invalid)', False, key_proto)


def _vary_signature_encodings() -> (
    Iterator[Tuple[str, bool, ecdsa_pb2.EcdsaPrivateKey]]
):
  """Returns keys with unsupported signature encodings."""

  key_proto = _basic_p256_key()
  key_proto.public_key.params.encoding = (
      ecdsa_pb2.EcdsaSignatureEncoding.UNKNOWN_ENCODING
  )
  yield ('UNKNOWN encoding (invalid)', False, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.encoding = (
      ecdsa_pb2.EcdsaSignatureEncoding.IEEE_P1363
  )
  yield ('IEEE_P1363 encoding', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.encoding = (
      ecdsa_pb2.EcdsaSignatureEncoding.DER
  )
  yield ('DER encoding', True, key_proto)


def _proto_keys() -> (
    Iterator[Tuple[str, bool, ecdsa_pb2.EcdsaPrivateKey]]
):
  """Returns triples (name, validity, proto) for EcdsaPrivateKey."""
  key_proto = _basic_p256_key()
  yield ('Basic P256Key', True, key_proto)

  key_proto = _short_p256_key()
  yield ('Short P256Key', True, key_proto)

  key_proto = _padded_p256_key()
  yield ('Padded P256Key', True, key_proto)

  key_proto = _basic_p384_key()
  yield ('Basic P384Key', True, key_proto)

  key_proto = _basic_p521_key()
  yield ('Basic P521Key', True, key_proto)

  key_proto = _basic_x25519_key()
  yield ('Basic X25519Key (invalid)', False, key_proto)

  for triple in _unsupported_hash_function_keys():
    yield triple

  for triple in _vary_signature_encodings():
    yield triple


def _output_prefix_types() -> (
    Iterator[Tuple[tink_pb2.OutputPrefixType, bool]]
):
  yield (tink_pb2.OutputPrefixType.UNKNOWN_PREFIX, False)
  yield (tink_pb2.OutputPrefixType.TINK, True)
  yield (tink_pb2.OutputPrefixType.LEGACY, True)
  yield (tink_pb2.OutputPrefixType.CRUNCHY, True)
  yield (tink_pb2.OutputPrefixType.RAW, True)


def ecdsa_private_keys() -> Iterator[test_key.TestKey]:
  """Returns private test keys for Ecdsa."""

  for (name, valid, key_proto) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=valid,
    )

  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=False,
  )

  for (output_prefix_type, valid) in _output_prefix_types():
    output_prefix_type_name = tink_pb2.OutputPrefixType.Name(output_prefix_type)
    yield test_key.TestKey(
        test_name=f'OutputPrefixType={output_prefix_type_name}',
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=_basic_p256_key().SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        output_prefix_type=output_prefix_type,
        valid=valid,
    )

  for name, wrong_version_key in _wrong_version_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=wrong_version_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=False,
    )


def ecdsa_public_keys() -> Iterator[test_key.TestKey]:
  """Returns public test keys for Ecdsa."""

  for (name, valid, key_proto) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=key_proto.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        valid=valid,
    )

  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      valid=False,
  )

  for (output_prefix_type, valid) in _output_prefix_types():
    output_prefix_type_name = tink_pb2.OutputPrefixType.Name(output_prefix_type)
    yield test_key.TestKey(
        test_name=f'OutputPrefixType={output_prefix_type_name}',
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=_basic_p256_key().public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        output_prefix_type=output_prefix_type,
        valid=valid,
    )
