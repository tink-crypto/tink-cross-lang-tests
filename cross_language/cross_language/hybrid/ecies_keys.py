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

"""Test keys for ECIES."""

import binascii
from typing import Iterator, Tuple

from tink.proto import common_pb2
from tink.proto import ecies_aead_hkdf_pb2
from tink.proto import tink_pb2
from cross_language import test_key
from cross_language.util import utilities


def _p256_point_x() -> bytes:
  return binascii.unhexlify(
      '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
  )


def _p256_point_y() -> bytes:
  return binascii.unhexlify(
      '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'
  )


def _p256_private_value() -> bytes:
  return binascii.unhexlify(
      'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'
  )


def _basic_p256_key() -> ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey:
  return ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey(
      version=0,
      public_key=ecies_aead_hkdf_pb2.EciesAeadHkdfPublicKey(
          version=0,
          params=ecies_aead_hkdf_pb2.EciesAeadHkdfParams(
              kem_params=ecies_aead_hkdf_pb2.EciesHkdfKemParams(
                  curve_type=common_pb2.EllipticCurveType.NIST_P256,
                  hkdf_hash_type=common_pb2.HashType.SHA1,
                  hkdf_salt=b'',
              ),
              dem_params=ecies_aead_hkdf_pb2.EciesAeadDemParams(
                  aead_dem=utilities.KEY_TEMPLATE['AES128_GCM']
              ),
              ec_point_format=common_pb2.EcPointFormat.COMPRESSED,
          ),
          x=_p256_point_x(),
          y=_p256_point_y(),
      ),
      key_value=_p256_private_value(),
  )


def _varied_hash_function() -> (
    Iterator[Tuple[str, bool, ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey]]
):
  """Returns triples (name, validity, proto) for EciesAeadHkdfPrivateKey."""
  key_proto = _basic_p256_key()
  yield ('Basic P256Key', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.kem_params.hkdf_hash_type = (
      common_pb2.HashType.SHA1
  )
  yield ('HashFunction: SHA1', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.kem_params.hkdf_hash_type = (
      common_pb2.HashType.SHA224
  )
  yield ('HashFunction: SHA224', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.kem_params.hkdf_hash_type = (
      common_pb2.HashType.SHA384
  )
  yield ('HashFunction: SHA384', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.kem_params.hkdf_hash_type = (
      common_pb2.HashType.SHA512
  )
  yield ('HashFunction: SHA512', True, key_proto)


def _varied_point_format() -> (
    Iterator[Tuple[str, bool, ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey]]
):
  """Returns triples (name, validity, proto) for EciesAeadHkdfPrivateKey."""
  key_proto = _basic_p256_key()
  key_proto.public_key.params.ec_point_format = (
      common_pb2.EcPointFormat.UNCOMPRESSED
  )
  yield ('EcPointFormat.UNCOMPRESSED', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.ec_point_format = (
      common_pb2.EcPointFormat.COMPRESSED
  )
  yield ('EcPointFormat.COMPRESSED', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.ec_point_format = (
      common_pb2.EcPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED
  )
  yield ('EcPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.ec_point_format = (
      common_pb2.EcPointFormat.UNKNOWN_FORMAT
  )
  yield ('EcPointFormat.UNKNOWN_FORMAT (invalid)', False, key_proto)


def _valid_xchacha_keys() -> (
    Iterator[Tuple[str, ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey]]
):
  key_proto = _basic_p256_key()
  key_proto.public_key.params.dem_params.aead_dem.CopyFrom(
      utilities.KEY_TEMPLATE['XCHACHA20_POLY1305']
  )
  yield ('XChaChaPoly201305', key_proto)


def ecies_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for ECIES."""

  for (name, valid, key_proto) in _varied_hash_function():
    yield test_key.TestKey(
        test_name=name,
        type_url=(
            'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey'
        ),
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=valid,
    )
  for (name, valid, key_proto) in _varied_point_format():
    yield test_key.TestKey(
        test_name=name,
        type_url=(
            'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey'
        ),
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=valid,
    )
  for (name, key_proto) in _valid_xchacha_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=(
            'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey'
        ),
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        supported_languages=['cc', 'python']
    )

  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=False,
  )
