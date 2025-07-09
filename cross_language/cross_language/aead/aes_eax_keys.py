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

"""Test keys for AES EAX."""

import os
from typing import Iterator, Tuple

from tink.proto import aes_eax_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _basic_key() -> aes_eax_pb2.AesEaxKey:
  return aes_eax_pb2.AesEaxKey(
      version=0,
      key_value=os.urandom(32),
      params=aes_eax_pb2.AesEaxParams(iv_size=12),
  )


def _proto_keys() -> Iterator[Tuple[str, bool, aes_eax_pb2.AesEaxKey]]:
  """Returns triples (name, validity, proto) for AesEaxKeys."""

  key = aes_eax_pb2.AesEaxKey(
      version=0,
      key_value=os.urandom(32),
      params=aes_eax_pb2.AesEaxParams(iv_size=12),
  )
  yield ('32 byte key', True, key)

  key.key_value = os.urandom(16)
  yield ('16 byte key', True, key)

  key.key_value = os.urandom(24)
  yield ('24 byte key (invalid)', False, key)

  key = aes_eax_pb2.AesEaxKey(
      version=0,
      key_value=os.urandom(32),
      params=aes_eax_pb2.AesEaxParams(iv_size=16),
  )
  yield ('IV Size 16', True, key)

  key.params.iv_size = 13
  yield ('IV Size 13 (invalid)', False, key)

  key.params.iv_size = 13
  yield ('IV Size 24 (invalid)', False, key)

  key = aes_eax_pb2.AesEaxKey(
      version=0,
      key_value=os.urandom(32),
  )
  yield ('Params not set', False, key)

  key = aes_eax_pb2.AesEaxKey(
      version=1,
      key_value=os.urandom(32),
      params=aes_eax_pb2.AesEaxParams(iv_size=12),
  )
  yield ('Version 1', False, key)


def aes_eax_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for AesEax."""
  for (name, valid, msg) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )

  yield test_key.TestKey(
      test_name='TINK key with 0 key_id',
      type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.TINK,
      key_id=0,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='CRUNCHY key',
      type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='LEGACY key',
      type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='RAW key',
      type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='UNKNOWN outputprefixtype key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.UNKNOWN_PREFIX,
      valid=False,
  )

  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.AesEaxKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=False,
  )
