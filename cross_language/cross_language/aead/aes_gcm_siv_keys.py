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

"""Test keys for AES GCM SIV."""

import os
from typing import Iterator, Tuple

from tink.proto import aes_gcm_siv_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _proto_keys() -> Iterator[Tuple[str, bool, aes_gcm_siv_pb2.AesGcmSivKey]]:
  """Returns triples (name, validity, proto) for AesGcmKeys."""

  key = aes_gcm_siv_pb2.AesGcmSivKey(
      version=0,
      key_value=os.urandom(32),
  )
  yield ('32 byte key', True, key)

  key.key_value = os.urandom(16)
  yield ('16 byte key', True, key)

  key.key_value = os.urandom(24)
  yield ('24 byte key (invalid)', False, key)

  key = aes_gcm_siv_pb2.AesGcmSivKey(
      version=1,
      key_value=os.urandom(32),
  )
  yield ('Version 1', False, key)


def aes_gcm_siv_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for AesGcmSiv."""
  for (name, valid, msg) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.AesGcmSivKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )

  yield test_key.TestKey(
      test_name='TINK key with 0 key_id',
      type_url='type.googleapis.com/google.crypto.tink.AesGcmSivKey',
      serialized_value=aes_gcm_siv_pb2.AesGcmSivKey(
          key_value=os.urandom(32)
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.TINK,
      key_id=0,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='CRUNCHY key',
      type_url='type.googleapis.com/google.crypto.tink.AesGcmKey',
      serialized_value=aes_gcm_siv_pb2.AesGcmSivKey(
          key_value=os.urandom(32)
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='LEGACY key',
      type_url='type.googleapis.com/google.crypto.tink.AesGcmKey',
      serialized_value=aes_gcm_siv_pb2.AesGcmSivKey(
          key_value=os.urandom(32)
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='RAW key',
      type_url='type.googleapis.com/google.crypto.tink.AesGcmKey',
      serialized_value=aes_gcm_siv_pb2.AesGcmSivKey(
          key_value=os.urandom(32)
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='UNKNOWN outputprefixtype key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.AesGcmKey',
      serialized_value=aes_gcm_siv_pb2.AesGcmSivKey(
          key_value=os.urandom(32)
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.UNKNOWN_PREFIX,
      valid=False,
  )

  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.AesGcmSivKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=False,
  )
