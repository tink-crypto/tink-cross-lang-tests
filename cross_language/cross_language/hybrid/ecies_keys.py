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

_PRIVATE_TYPE_URL = 'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey'
_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey'


def _p256_point_x() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'
  )


def _p256_point_y() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'
  )


def _p256_private_value() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'
  )


def _p384_point_x() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '009d92e0330dfc60ba8b2be32e10f7d2f8457678a112cafd4544b29b7e6addf0249968f54c732aa49bc4a38f467edb8424'
  )


def _p384_point_y() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '0081a3a9c9e878b86755f018a8ec3c5e80921910af919b95f18976e35acc04efa2962e277a0b2c990ae92b62d6c75180ba'
  )


def _p384_private_value() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '670dc60402d8a4fe52f4e552d2b71f0f81bcf195d8a71a6c7d84efb4f0e4b4a5d0f60a27c94caac46bdeeb79897a3ed9'
  )


def _p521_point_x() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4'
  )


def _p521_point_y() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5'
  )


def _p521_private_value() -> bytes:
  """All test values are obtained from Java (see EciesAeadHkdfTestUtil.java)."""
  return binascii.unhexlify(
      '00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538'
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


def _invalid_long_p256_key() -> ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey:
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
      key_value=b'\x11' + _p256_private_value(),
  )


def _basic_p384_key() -> ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey:
  return ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey(
      version=0,
      public_key=ecies_aead_hkdf_pb2.EciesAeadHkdfPublicKey(
          version=0,
          params=ecies_aead_hkdf_pb2.EciesAeadHkdfParams(
              kem_params=ecies_aead_hkdf_pb2.EciesHkdfKemParams(
                  curve_type=common_pb2.EllipticCurveType.NIST_P384,
                  hkdf_hash_type=common_pb2.HashType.SHA384,
                  hkdf_salt=b'',
              ),
              dem_params=ecies_aead_hkdf_pb2.EciesAeadDemParams(
                  aead_dem=utilities.KEY_TEMPLATE['AES128_GCM']
              ),
              ec_point_format=common_pb2.EcPointFormat.COMPRESSED,
          ),
          x=_p384_point_x(),
          y=_p384_point_y(),
      ),
      key_value=_p384_private_value(),
  )


def _basic_p521_key() -> ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey:
  return ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey(
      version=0,
      public_key=ecies_aead_hkdf_pb2.EciesAeadHkdfPublicKey(
          version=0,
          params=ecies_aead_hkdf_pb2.EciesAeadHkdfParams(
              kem_params=ecies_aead_hkdf_pb2.EciesHkdfKemParams(
                  curve_type=common_pb2.EllipticCurveType.NIST_P521,
                  hkdf_hash_type=common_pb2.HashType.SHA512,
                  hkdf_salt=b'',
              ),
              dem_params=ecies_aead_hkdf_pb2.EciesAeadDemParams(
                  aead_dem=utilities.KEY_TEMPLATE['AES128_GCM']
              ),
              ec_point_format=common_pb2.EcPointFormat.COMPRESSED,
          ),
          x=_p521_point_x(),
          y=_p521_point_y(),
      ),
      key_value=_p521_private_value(),
  )


def _wrong_version_keys() -> (
    Iterator[Tuple[str, ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey]]
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


def _varied_aead_dem_key_template_output_prefix() -> (
    Iterator[Tuple[str, bool, ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey]]
):
  """The OutputPrefix in the DEM Key Template is ignored."""
  key_proto = _basic_p256_key()
  key_proto.public_key.params.dem_params.aead_dem.output_prefix_type = (
      tink_pb2.OutputPrefixType.RAW
  )
  yield ('DEM OutputPrefix RAW', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.dem_params.aead_dem.output_prefix_type = (
      tink_pb2.OutputPrefixType.CRUNCHY
  )
  yield ('DEM OutputPrefix CRUNCHY', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.dem_params.aead_dem.output_prefix_type = (
      tink_pb2.OutputPrefixType.LEGACY
  )
  yield ('DEM OutputPrefix LEGACY', True, key_proto)

  key_proto = _basic_p256_key()
  key_proto.public_key.params.dem_params.aead_dem.output_prefix_type = (
      tink_pb2.OutputPrefixType.UNKNOWN_PREFIX
  )
  yield ('DEM OutputPrefix UNKNOWN_PREFIX', True, key_proto)


def _proto_private_keys() -> (
    Iterator[Tuple[str, bool, ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey]]
):
  yield ('Basic P256 Key', True, _basic_p256_key())
  yield ('Basic P384 Key', True, _basic_p384_key())
  yield ('Basic P521 Key', True, _basic_p521_key())
  for triple in _varied_hash_function():
    yield triple
  for triple in _varied_point_format():
    yield triple
  for triple in _varied_aead_dem_key_template_output_prefix():
    yield triple


def _valid_xchacha_keys() -> (
    Iterator[Tuple[str, ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey]]
):
  key_proto = _basic_p256_key()
  key_proto.public_key.params.dem_params.aead_dem.CopyFrom(
      utilities.KEY_TEMPLATE['XCHACHA20_POLY1305']
  )
  yield ('XChaChaPoly201305', key_proto)


def _output_prefix_with_validity() -> (
    Iterator[Tuple[str, bool, tink_pb2.OutputPrefixType]]
):
  yield ('RAW Key', True, tink_pb2.OutputPrefixType.RAW)
  yield ('CRUNCHY Key', True, tink_pb2.OutputPrefixType.CRUNCHY)
  yield ('LEGACY Key', True, tink_pb2.OutputPrefixType.LEGACY)
  yield ('UNKOWN_PREFIX', False, tink_pb2.OutputPrefixType.UNKNOWN_PREFIX)


def ecies_private_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for ECIES (EciesAeadHkdfPrivateKey)."""

  for (name, valid, key_proto) in _proto_private_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=valid,
    )

  for (name, key_proto) in _valid_xchacha_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=True,
        tags=['b/315928577'],
    )

  for (name, valid, output_prefix_type) in _output_prefix_with_validity():
    yield test_key.TestKey(
        test_name=name,
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

    # Invalid key
    yield test_key.TestKey(
        test_name='Invalid key with too long private key',
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=_invalid_long_p256_key().SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=False,
        tags=['b/480094023'],
    )

  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url=_PRIVATE_TYPE_URL,
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      valid=False,
  )


def ecies_public_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for ECIES (EciesAeadHkdfPublicKey)."""

  for (name, valid, key_proto) in _proto_private_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=key_proto.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        valid=valid,
    )

  for (name, key_proto) in _valid_xchacha_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=key_proto.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        valid=True,
        tags=['b/315928577'],
    )

  for (name, valid, output_prefix_type) in _output_prefix_with_validity():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=_basic_p256_key().public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        output_prefix_type=output_prefix_type,
        valid=valid,
    )

  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url=_PUBLIC_TYPE_URL,
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      valid=False,
  )
