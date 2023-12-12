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

"""Test keys for AesCtrHmacAead."""

import os
from typing import Iterator, Tuple

from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import aes_ctr_pb2
from tink.proto import common_pb2
from tink.proto import hmac_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _basic_key() -> aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey:
  """Returns triples a valid AesCtrHmacAeadKey proto."""

  return aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey(
      version=0,
      aes_ctr_key=aes_ctr_pb2.AesCtrKey(
          version=0,
          params=aes_ctr_pb2.AesCtrParams(iv_size=16),
          key_value=os.urandom(16),
      ),
      hmac_key=hmac_pb2.HmacKey(
          version=0,
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
          key_value=os.urandom(16),
      ),
  )


def _proto_keys_sha1() -> (
    Iterator[Tuple[str, bool, aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey]]
):
  """Returns triples (name, validity, proto) for keys using SHA1."""

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA1
  yield ('Basic SHA1 key', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA1
  key.hmac_key.params.tag_size = 15
  yield ('SHA1, Tag size 15', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA1
  key.hmac_key.params.tag_size = 20
  yield ('SHA1, Tag size 20', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA1
  key.hmac_key.params.tag_size = 9
  yield ('SHA1, Tag size 9 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA1
  key.hmac_key.params.tag_size = 21
  yield ('SHA1, Tag size 21 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA1
  key.hmac_key.key_value = os.urandom(1000)
  yield ('SHA1, large key size', True, key)


def _proto_keys_sha224() -> (
    Iterator[Tuple[str, bool, aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey]]
):
  """Returns triples (name, validity, proto) for keys using SHA224."""

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA224
  yield ('Basic SHA224 key', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA224
  key.hmac_key.params.tag_size = 15
  yield ('SHA224, Tag size 15', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA224
  key.hmac_key.params.tag_size = 28
  yield ('SHA224, Tag size 28', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA224
  key.hmac_key.params.tag_size = 9
  yield ('SHA224, Tag size 9 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA224
  key.hmac_key.params.tag_size = 29
  yield ('SHA224, Tag size 29 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA224
  key.hmac_key.key_value = os.urandom(1000)
  yield ('SHA224, large key size', True, key)


def _proto_keys_sha256() -> (
    Iterator[Tuple[str, bool, aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey]]
):
  """Returns triples (name, validity, proto) for keys using SHA256."""

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA256
  yield ('Basic SHA256 key', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA256
  key.hmac_key.params.tag_size = 15
  yield ('SHA256, Tag size 15', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA256
  key.hmac_key.params.tag_size = 32
  yield ('SHA256, Tag size 32', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA256
  key.hmac_key.params.tag_size = 9
  yield ('SHA256, Tag size 9 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA256
  key.hmac_key.params.tag_size = 33
  yield ('SHA256, Tag size 33 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA256
  key.hmac_key.key_value = os.urandom(1000)
  yield ('SHA256, large key size', True, key)


def _proto_keys_sha384() -> (
    Iterator[Tuple[str, bool, aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey]]
):
  """Returns triples (name, validity, proto) for keys using SHA384."""

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA384
  yield ('Basic SHA384 key', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA384
  key.hmac_key.params.tag_size = 15
  yield ('SHA384, Tag size 15', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA384
  key.hmac_key.params.tag_size = 48
  yield ('SHA384, Tag size 48', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA384
  key.hmac_key.params.tag_size = 9
  yield ('SHA384, Tag size 9 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA384
  key.hmac_key.params.tag_size = 49
  yield ('SHA384, Tag size 49 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA384
  key.hmac_key.key_value = os.urandom(1000)
  yield ('SHA384, large key size', True, key)


def _proto_keys_sha512() -> (
    Iterator[Tuple[str, bool, aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey]]
):
  """Returns triples (name, validity, proto) for keys using SHA512."""

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA512
  yield ('Basic SHA512 key', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA512
  yield ('SHA512, Tag size 15', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA512
  key.hmac_key.params.tag_size = 64
  yield ('SHA512, Tag size 64', True, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA512
  key.hmac_key.params.tag_size = 9
  yield ('SHA512, Tag size 9 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA512
  key.hmac_key.params.tag_size = 65
  yield ('SHA512, Tag size 56 (invalid)', False, key)

  key = _basic_key()
  key.hmac_key.params.hash = common_pb2.HashType.SHA512
  key.hmac_key.key_value = os.urandom(1000)
  yield ('SHA512, large key size', True, key)


def _proto_keys_vary_aes_ctr() -> (
    Iterator[Tuple[str, bool, aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey]]
):
  """Returns triples (name, validity, proto) for keys using SHA1."""

  key = _basic_key()
  key.aes_ctr_key.params.iv_size = 11
  yield ('AES CTR iv size 11 (invalid)', False, key)

  key = _basic_key()
  key.aes_ctr_key.params.iv_size = 12
  yield ('AES CTR iv size 12', True, key)

  key = _basic_key()
  key.aes_ctr_key.params.iv_size = 13
  yield ('AES CTR iv size 13', True, key)

  key = _basic_key()
  key.aes_ctr_key.params.iv_size = 14
  yield ('AES CTR iv size 14', True, key)

  key = _basic_key()
  key.aes_ctr_key.params.iv_size = 15
  yield ('AES CTR iv size 15', True, key)

  key = _basic_key()
  key.aes_ctr_key.params.iv_size = 16
  yield ('AES CTR iv size 16', True, key)

  key = _basic_key()
  key.aes_ctr_key.params.iv_size = 17
  yield ('AES CTR iv size 17 (invalid)', False, key)

  key = _basic_key()
  key.aes_ctr_key.key_value = os.urandom(32)
  yield ('AES CTR 32 byte key', True, key)

  key = _basic_key()
  key.aes_ctr_key.key_value = os.urandom(24)
  yield ('AES CTR 24 byte key (invalid)', False, key)


def _invalid_version_keys() -> (
    Iterator[Tuple[str, bool, aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey]]
):
  """Returns triples (name, validity, proto) where version is 1 somewhere."""

  key = _basic_key()
  key.hmac_key.version = 1
  yield ('HMac Key version 1 (invalid)', False, key)

  key = _basic_key()
  key.aes_ctr_key.version = 1
  yield ('AES CTR Key version 1 (invalid)', False, key)

  key = _basic_key()
  key.version = 1
  yield ('Version 1 (invalid)', False, key)


def _proto_keys() -> (
    Iterator[Tuple[str, bool, aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey]]
):
  """Returns triples (name, validity, proto) for AesCtrHmacAeadKeys."""

  for triple in _proto_keys_sha1():
    yield triple
  for triple in _proto_keys_sha224():
    yield triple
  for triple in _proto_keys_sha256():
    yield triple
  for triple in _proto_keys_sha384():
    yield triple
  for triple in _proto_keys_sha512():
    yield triple
  for triple in _proto_keys_vary_aes_ctr():
    yield triple
  for triple in _invalid_version_keys():
    yield triple


def aes_ctr_hmac_aead_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for AesCtrHmacAeadKey."""
  for (name, valid, msg) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )

  yield test_key.TestKey(
      test_name='CRUNCHY key',
      type_url='type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='LEGACY key',
      type_url='type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='RAW key',
      type_url='type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='UNKNOWN outputprefixtype key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.UNKNOWN_PREFIX,
      valid=False,
  )

  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=False,
  )
