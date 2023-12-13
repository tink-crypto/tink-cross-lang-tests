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

"""Test keys for JWT HMAC."""

import os
from typing import Iterator, Tuple

from tink.proto import jwt_hmac_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _basic_proto_key() -> jwt_hmac_pb2.JwtHmacKey:
  return jwt_hmac_pb2.JwtHmacKey(
      version=0,
      algorithm=jwt_hmac_pb2.JwtHmacAlgorithm.HS256,
      key_value=os.urandom(32),
  )


def _custom_kid_key(custom_kid: str) -> jwt_hmac_pb2.JwtHmacKey:
  return jwt_hmac_pb2.JwtHmacKey(
      version=0,
      algorithm=jwt_hmac_pb2.JwtHmacAlgorithm.HS256,
      key_value=os.urandom(32),
      custom_kid=jwt_hmac_pb2.JwtHmacKey.CustomKid(
          value=custom_kid,
      ),
  )


def _proto_keys_hs256() -> Iterator[Tuple[str, bool, jwt_hmac_pb2.JwtHmacKey]]:
  """Returns triples (name, validity, proto) for JwtHmacKeys, HashType=SHA1."""

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS256
  yield ('Basic HS256 key', True, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS256
  key.key_value = os.urandom(31)
  yield ('31 bytes HS256 key (invalid)', False, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS256
  key.key_value = os.urandom(33)
  yield ('33 bytes HS256 key', True, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS256
  key.key_value = os.urandom(64)
  yield ('64 bytes HS256 key', True, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS256
  key.key_value = os.urandom(778899)
  yield ('778899 bytes HS256 key', True, key)


def _proto_keys_hs384() -> Iterator[Tuple[str, bool, jwt_hmac_pb2.JwtHmacKey]]:
  """Returns triples (name, validity, proto) for JwtHmacKeys, HashType=SHA1."""

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS384
  key.key_value = os.urandom(48)
  yield ('Basic HS384 key', True, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS384
  key.key_value = os.urandom(47)
  yield ('47 bytes HS384 key (invalid)', False, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS384
  key.key_value = os.urandom(50)
  yield ('50 bytes HS384 key', True, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS384
  key.key_value = os.urandom(64)
  yield ('64 bytes HS384 key', True, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS384
  key.key_value = os.urandom(778899)
  yield ('778899 bytes HS384 key', True, key)


def _proto_keys_hs512() -> Iterator[Tuple[str, bool, jwt_hmac_pb2.JwtHmacKey]]:
  """Returns triples (name, validity, proto) for JwtHmacKeys, HashType=SHA1."""

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS512
  key.key_value = os.urandom(64)
  yield ('Basic HS512 key', True, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS512
  key.key_value = os.urandom(63)
  yield ('63 bytes HS512 key (invalid)', False, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS512
  key.key_value = os.urandom(32)
  yield ('32 bytes HS512 key (invalid)', False, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS512
  key.key_value = os.urandom(128)
  yield ('64 bytes HS512 key', True, key)

  key = _basic_proto_key()
  key.algorithm = jwt_hmac_pb2.JwtHmacAlgorithm.HS512
  key.key_value = os.urandom(778899)
  yield ('778899 bytes HS384 key', True, key)


def _proto_keys() -> Iterator[Tuple[str, bool, jwt_hmac_pb2.JwtHmacKey]]:
  for triple in _proto_keys_hs256():
    yield triple
  for triple in _proto_keys_hs384():
    yield triple
  for triple in _proto_keys_hs512():
    yield triple


def jwt_hmac_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HMac."""
  for (name, valid, msg) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )

  yield test_key.TestKey(
      test_name='RAW key',
      type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
      # CustomKid is absent
      serialized_value=_basic_proto_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=True,
  )

  yield test_key.TestKey(
      test_name='CustomKid & Tink Key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
      serialized_value=_custom_kid_key('').SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.TINK,
      valid=False,
      tags=['b/315970600'],
  )

  yield test_key.TestKey(
      test_name='CRUNCHY key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
      serialized_value=_basic_proto_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      tags=['b/315970619'],
      valid=False,
  )

  yield test_key.TestKey(
      test_name='LEGACY key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
      serialized_value=_basic_proto_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      tags=['b/315970619'],
      valid=False,
  )
