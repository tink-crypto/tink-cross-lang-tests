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

"""Test keys for HMAC."""

import os
from typing import Iterator, Tuple

from tink.proto import common_pb2
from tink.proto import hmac_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _proto_keys() -> Iterator[Tuple[str, bool, hmac_pb2.HmacKey]]:
  """Returns triples (name, validity, proto) for HmacKeys."""

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA1, tag_size=10
      ),
  )
  yield ('Basic key', True, key)

  ## SHA1 Tag Sizes
  key.params.tag_size = 15
  yield ('Tag Size 15', True, key)

  key.params.tag_size = 20
  yield ('Tag Size 20', True, key)

  key.params.tag_size = 21
  yield ('Tag Size 21 (invalid)', False, key)

  key.params.tag_size = 9
  yield ('Tag Size 9 (invalid)', False, key)

  ## SHA224 Tag Sizes:
  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA224, tag_size=10
      ),
  )
  yield ('SHA224', True, key)

  key.params.tag_size = 10
  yield ('SHA224 Tag Size 10', True, key)

  key.params.tag_size = 9
  yield ('SHA224 Tag Size 9 (invalid)', False, key)

  key.params.tag_size = 28
  yield ('SHA224 Tag Size 28', True, key)

  key.params.tag_size = 29
  yield ('SHA224 Tag Size 29 (invalid)', False, key)


def hmac_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HMac."""
  for (name, valid, msg) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=valid,
    )
  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.HmacKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      valid=False,
  )
