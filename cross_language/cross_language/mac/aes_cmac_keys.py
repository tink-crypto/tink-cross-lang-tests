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

"""Test keys for AES CMAC."""

import os
from typing import Iterator, Tuple

from tink.proto import aes_cmac_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _proto_keys() -> Iterator[Tuple[str, bool, aes_cmac_pb2.AesCmacKey]]:
  """Returns triples (name, validity, proto) for AesCmacKeys."""

  key = aes_cmac_pb2.AesCmacKey(
      version=0,
      key_value=os.urandom(32),
      params=aes_cmac_pb2.AesCmacParams(tag_size=10),
  )
  yield ('Basic', True, key)

  key.key_value = os.urandom(16)
  yield ('Invalid 16 byte key', False, key)

  key.key_value = os.urandom(24)
  yield ('Invalid 24 byte key', False, key)

  key.key_value = os.urandom(31)
  yield ('Invalid 31 byte key', False, key)

  key = aes_cmac_pb2.AesCmacKey(
      version=0,
      key_value=os.urandom(32),
      params=aes_cmac_pb2.AesCmacParams(tag_size=10),
  )
  yield ('Tag size 10', True, key)

  key.params.tag_size = 11
  yield ('Tag size 11', True, key)

  key.params.tag_size = 12
  yield ('Tag size 12', True, key)

  key.params.tag_size = 13
  yield ('Tag size 13', True, key)

  key.params.tag_size = 14
  yield ('Tag size 14', True, key)

  key.params.tag_size = 15
  yield ('Tag size 15', True, key)

  key.params.tag_size = 16
  yield ('Tag size 16', True, key)

  key.params.tag_size = 17
  yield ('Invalid Tag size 17', False, key)

  key.params.tag_size = 9
  yield ('Invalid Tag size 9', False, key)


def aes_cmac_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for AesCmac."""
  for (name, valid, msg) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.AesCmacKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )
  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.AesCmacKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=False,
  )
