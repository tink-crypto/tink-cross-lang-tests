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

"""Test keys for AES SIV."""

import binascii
import os
from typing import Iterator, Tuple

from tink.proto import aes_siv_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _proto_keys() -> Iterator[Tuple[str, bool, aes_siv_pb2.AesSivKey]]:
  """Returns triples (name, validity, proto) for AesSivKeys."""

  key = aes_siv_pb2.AesSivKey(
      version=0,
      key_value=os.urandom(64),
  )
  yield ('Basic key', True, key)

  key.key_value = os.urandom(128)
  yield ('128 byte key (invalid)', False, key)

  key.key_value = os.urandom(32)
  yield ('32 byte key (invalid)', False, key)

  key = aes_siv_pb2.AesSivKey(
      version=1,
      key_value=os.urandom(64),
  )
  yield ('Version 1 key (invalid)', False, key)


def _proto_stress_test_key() -> test_key.TestKey:
  """Returns a key using details of how proto serializes."""

  # Proto will ignore unknown fields and use the last entry.
  # 0x1801 is the serialization of a int32 field with tag 3 and value 1.
  # 0x2001 is the serialization of a int32 field with tag 4 and value 1.
  int32_tag3_value1 = binascii.unhexlify('1801')
  # This will be ignored: when non-repeated fields repeat, proto uses the last
  # instance
  ignored_key = aes_siv_pb2.AesSivKey(
      key_value=os.urandom(17),
  ).SerializeToString()
  key = aes_siv_pb2.AesSivKey(
      key_value=os.urandom(64),
  ).SerializeToString()
  int32_tag4_value1 = binascii.unhexlify('2001')
  return test_key.TestKey(
      test_name='Proto stress test',
      type_url='type.googleapis.com/google.crypto.tink.AesSivKey',
      serialized_value=int32_tag3_value1
      + ignored_key
      + key  # Overwrites the "ignored_key"
      + int32_tag4_value1,
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=True,
  )


def _key_with_output_prefix_type(
    output_prefix_type: tink_pb2.OutputPrefixType,
) -> test_key.TestKey:
  output_prefix_type_name = tink_pb2.OutputPrefixType.Name(output_prefix_type)
  return test_key.TestKey(
      test_name=f'{output_prefix_type_name} key',
      type_url='type.googleapis.com/google.crypto.tink.AesSivKey',
      serialized_value=aes_siv_pb2.AesSivKey(
          version=0,
          key_value=os.urandom(64),
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=output_prefix_type,
      valid=True,
  )


def aes_siv_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HMac."""
  for (name, valid, msg) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.AesSivKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )

  yield _key_with_output_prefix_type(tink_pb2.OutputPrefixType.RAW)
  yield _key_with_output_prefix_type(tink_pb2.OutputPrefixType.TINK)
  yield _key_with_output_prefix_type(tink_pb2.OutputPrefixType.CRUNCHY)
  yield _key_with_output_prefix_type(tink_pb2.OutputPrefixType.LEGACY)
  yield _proto_stress_test_key()

  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.AesSivKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=False,
  )
