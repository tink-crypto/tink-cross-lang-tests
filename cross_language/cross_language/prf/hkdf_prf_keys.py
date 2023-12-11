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

"""Test keys for HMAC PRF."""


import os
from typing import Iterator, Tuple

from tink.proto import common_pb2
from tink.proto import hkdf_prf_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _basic_key() -> hkdf_prf_pb2.HkdfPrfKey:
  return hkdf_prf_pb2.HkdfPrfKey(
      version=0,
      key_value=os.urandom(32),
      params=hkdf_prf_pb2.HkdfPrfParams(hash=common_pb2.HashType.SHA256),
  )


def _proto_keys_() -> Iterator[Tuple[str, bool, hkdf_prf_pb2.HkdfPrfKey]]:
  """Returns triples (name, validity, proto) for HmacPrfKey, HashType=SHA256."""

  key = _basic_key()
  yield ('Basic Key', True, key)

  key = _basic_key()
  key.key_value = os.urandom(31)
  yield ('31 Byte Key (invalid)', False, key)

  key = _basic_key()
  key.key_value = os.urandom(33)
  yield ('33 Byte Key', True, key)

  key = _basic_key()
  key.key_value = os.urandom(777)
  yield ('777 Byte Key', True, key)

  key = _basic_key()
  key.params.hash = common_pb2.HashType.UNKNOWN_HASH
  yield ('UNKNOWN_HASH key (invalid)', False, key)

  key = _basic_key()
  key.params.hash = common_pb2.HashType.SHA1
  yield ('SHA1 key (invalid)', False, key)

  key = _basic_key()
  key.params.hash = common_pb2.HashType.SHA224
  yield ('SHA224 key (invalid)', False, key)

  key = _basic_key()
  key.params.hash = common_pb2.HashType.SHA384
  yield ('SHA384 key (invalid)', False, key)

  key = _basic_key()
  key.params.hash = common_pb2.HashType.SHA512
  yield ('SHA512 key', True, key)

  key = _basic_key()
  key.params.salt = os.urandom(12)
  yield ('12 byte random salt', True, key)

  key = _basic_key()
  key.version = 1
  yield ('Version 1 key (invalid)', False, key)


def hkdf_prf_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HKDF."""
  for (name, valid, msg) in _proto_keys_():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.HkdfPrfKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        output_prefix_type=tink_pb2.OutputPrefixType.RAW,
        valid=valid,
    )
  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.HkdfPrfKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=False,
  )
