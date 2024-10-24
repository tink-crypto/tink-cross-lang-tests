# Copyright 2024 Google LLC
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

"""Test keys for X-AES-GCM."""

import os
from typing import Iterator, Tuple

from tink.proto import tink_pb2
from tink.proto import x_aes_gcm_pb2
from cross_language import test_key


def _new_x_aes_gcm_key(
    key_size: int, salt_size: int, version=0
) -> x_aes_gcm_pb2.XAesGcmKey:
  return x_aes_gcm_pb2.XAesGcmKey(
      version=version,
      params=x_aes_gcm_pb2.XAesGcmParams(salt_size=salt_size),
      key_value=os.urandom(key_size),
  )


def _basic_key() -> x_aes_gcm_pb2.XAesGcmKey:
  return _new_x_aes_gcm_key(key_size=32, salt_size=12)


def _proto_keys() -> Iterator[Tuple[str, bool, x_aes_gcm_pb2.XAesGcmKey]]:
  """Returns triples (name, validity, proto) for AesGcmKeys."""

  for salt_size in (8, 12):
    yield (
        f'{salt_size} bytes salt',
        True,
        _new_x_aes_gcm_key(32, salt_size),
    )
  for salt_size in (7, 13):
    yield (
        f'{salt_size} bytes salt (invalid)',
        False,
        _new_x_aes_gcm_key(32, salt_size),
    )
  yield (
      '24 byte key (invalid)',
      False,
      _new_x_aes_gcm_key(key_size=24, salt_size=8),
  )
  yield (
      'Version 1 (invalid)',
      False,
      _new_x_aes_gcm_key(key_size=32, salt_size=8, version=1),
  )


def x_aes_gcm_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for AesGcm."""
  for name, valid, msg in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.XAesGcmKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )
  yield test_key.TestKey(
      test_name='RAW key',
      type_url='type.googleapis.com/google.crypto.tink.XAesGcmKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=True,
  )
  # X-AES-GCM only supports RAW and TINK output prefix types.
  yield test_key.TestKey(
      test_name='CRUNCHY key',
      type_url='type.googleapis.com/google.crypto.tink.XAesGcmKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      valid=False,
  )
  yield test_key.TestKey(
      test_name='LEGACY key',
      type_url='type.googleapis.com/google.crypto.tink.XAesGcmKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      valid=False,
  )
  yield test_key.TestKey(
      test_name='UNKNOWN outputprefixtype key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.XAesGcmKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.UNKNOWN_PREFIX,
      valid=False,
  )
  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.XAesGcmKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=False,
  )
