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

"""Test keys for XChaCha20Poly1305."""

import os
from typing import Iterator, Tuple

from tink.proto import tink_pb2
from tink.proto import xchacha20_poly1305_pb2
from cross_language import test_key


_TYPE_URL = 'type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key'


def _proto_keys() -> (
    Iterator[Tuple[str, bool, xchacha20_poly1305_pb2.XChaCha20Poly1305Key]]
):
  """Returns triples (name, validity, proto) for XChaCha20Poly1305Keys."""

  key = xchacha20_poly1305_pb2.XChaCha20Poly1305Key(
      version=0,
      key_value=os.urandom(32),
  )
  yield ('32 byte key', True, key)

  key = xchacha20_poly1305_pb2.XChaCha20Poly1305Key(
      version=0,
      key_value=os.urandom(16),
  )
  yield ('16 byte key (invalid)', False, key)

  key = xchacha20_poly1305_pb2.XChaCha20Poly1305Key(
      version=0,
      key_value=os.urandom(64),
  )
  yield ('64 byte key (invalid)', False, key)

  key = xchacha20_poly1305_pb2.XChaCha20Poly1305Key(
      version=1,
      key_value=os.urandom(32),
  )
  yield ('version 1 key (invalid)', False, key)


def xchacha20_poly1305_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for XChaCha20Poly1305Keys."""
  for (name, valid, msg) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_TYPE_URL,
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )
  yield test_key.TestKey(
      test_name='RAW key',
      type_url=_TYPE_URL,
      serialized_value=xchacha20_poly1305_pb2.XChaCha20Poly1305Key(
          key_value=os.urandom(32)
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='CRUNCHY key',
      type_url=_TYPE_URL,
      serialized_value=xchacha20_poly1305_pb2.XChaCha20Poly1305Key(
          key_value=os.urandom(32)
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      valid=True,
  )
  yield test_key.TestKey(
      test_name='LEGACY key',
      type_url=_TYPE_URL,
      serialized_value=xchacha20_poly1305_pb2.XChaCha20Poly1305Key(
          key_value=os.urandom(32)
      ).SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      valid=True,
  )
  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url=_TYPE_URL,
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=False,
  )
