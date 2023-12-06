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


def _proto_keys_sha1() -> Iterator[Tuple[str, bool, hmac_pb2.HmacKey]]:
  """Returns triples (name, validity, proto) for HmacKeys, HashType=SHA1."""

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA1, tag_size=10
      ),
  )
  yield ('Basic SHA1 key', True, key)

  key.params.tag_size = 15
  yield ('SHA1, Tag Size 15', True, key)

  key.params.tag_size = 20
  yield ('SHA1, Tag Size 20', True, key)

  key.params.tag_size = 21
  yield ('SHA1, Tag Size 21 (invalid)', False, key)

  key.params.tag_size = 9
  yield ('SHA1, Tag Size 9 (invalid)', False, key)

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA1, tag_size=10
      ),
  )
  yield ('SHA1, Key Size 16', True, key)

  key.key_value = os.urandom(15)
  yield ('SHA1, Key Size 15 (invalid)', False, key)

  key.key_value = os.urandom(8)
  yield ('SHA1, Key Size 8 (invalid)', False, key)

  key.key_value = os.urandom(27)
  yield ('SHA1, Key Size 27', True, key)

  key.key_value = os.urandom(1020304)
  yield ('SHA1, Key Size 1020304', True, key)


def _proto_keys_sha224() -> Iterator[Tuple[str, bool, hmac_pb2.HmacKey]]:
  """Returns triples (name, validity, proto) for HmacKeys, HashType=SHA224."""

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA224, tag_size=10
      ),
  )
  yield ('Basic SHA224 key', True, key)

  key.params.tag_size = 15
  yield ('SHA224, Tag Size 15', True, key)

  key.params.tag_size = 28
  yield ('SHA224, Tag Size 28', True, key)

  key.params.tag_size = 29
  yield ('SHA224, Tag Size 29 (invalid)', False, key)

  key.params.tag_size = 9
  yield ('SHA224, Tag Size 9 (invalid)', False, key)

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA224, tag_size=10
      ),
  )
  yield ('SHA224, Key Size 16', True, key)

  key.key_value = os.urandom(15)
  yield ('SHA224, Key Size 15 (invalid)', False, key)

  key.key_value = os.urandom(8)
  yield ('SHA224, Key Size 8 (invalid)', False, key)

  key.key_value = os.urandom(32)
  yield ('SHA224, Key Size 32', True, key)

  key.key_value = os.urandom(1020304)
  yield ('SHA224, Key Size 1020304', True, key)


def _proto_keys_sha256() -> Iterator[Tuple[str, bool, hmac_pb2.HmacKey]]:
  """Returns triples (name, validity, proto) for HmacKeys, HashType=SHA256."""

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA256, tag_size=10
      ),
  )
  yield ('Basic SHA256 key', True, key)

  key.params.tag_size = 10
  yield ('SHA256, Tag Size 10', True, key)

  key.params.tag_size = 32
  yield ('SHA256, Tag Size 32', True, key)

  key.params.tag_size = 33
  yield ('SHA256, Tag Size 33 (invalid)', False, key)

  key.params.tag_size = 9
  yield ('SHA256, Tag Size 9 (invalid)', False, key)

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA256, tag_size=10
      ),
  )
  key.key_value = os.urandom(15)
  yield ('SHA256, Key Size 15 (invalid)', False, key)

  key.key_value = os.urandom(8)
  yield ('SHA256, Key Size 8 (invalid)', False, key)

  key.key_value = os.urandom(32)
  yield ('SHA256, Key Size 32', True, key)

  key.key_value = os.urandom(1020304)
  yield ('SHA256, Key Size 1020304', True, key)


def _proto_keys_sha384() -> Iterator[Tuple[str, bool, hmac_pb2.HmacKey]]:
  """Returns triples (name, validity, proto) for HmacKeys, HashType=SHA512."""

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA384, tag_size=10
      ),
  )
  yield ('Basic SHA384 key', True, key)

  key.params.tag_size = 10
  yield ('SHA384, Tag Size 10', True, key)

  key.params.tag_size = 48
  yield ('SHA384, Tag Size 48', True, key)

  key.params.tag_size = 49
  yield ('SHA384, Tag Size 49 (invalid)', False, key)

  key.params.tag_size = 9
  yield ('SHA384, Tag Size 9 (invalid)', False, key)

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA384, tag_size=10
      ),
  )
  yield ('SHA384, Key Size 16', True, key)

  key.key_value = os.urandom(15)
  yield ('SHA384, Key Size 15 (invalid)', False, key)

  key.key_value = os.urandom(8)
  yield ('SHA384, Key Size 8 (invalid)', False, key)

  key.key_value = os.urandom(32)
  yield ('SHA384, Key Size 32', True, key)

  key.key_value = os.urandom(1020304)
  yield ('SHA384, Key Size 1020304', True, key)


def _proto_keys_sha512() -> Iterator[Tuple[str, bool, hmac_pb2.HmacKey]]:
  """Returns triples (name, validity, proto) for HmacKeys, HashType=SHA512."""

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA512, tag_size=10
      ),
  )
  yield ('Basic SHA512 key', True, key)

  key.params.tag_size = 10
  yield ('SHA512, Tag Size 10', True, key)

  key.params.tag_size = 64
  yield ('SHA512, Tag Size 64', True, key)

  key.params.tag_size = 65
  yield ('SHA512, Tag Size 65 (invalid)', False, key)

  key.params.tag_size = 9
  yield ('SHA512, Tag Size 9 (invalid)', False, key)

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA512, tag_size=10
      ),
  )
  yield ('SHA512, Key Size 16', True, key)

  key.key_value = os.urandom(15)
  yield ('SHA512, Key Size 15 (invalid)', False, key)

  key.key_value = os.urandom(8)
  yield ('SHA512, Key Size 8 (invalid)', False, key)

  key.key_value = os.urandom(17)
  yield ('SHA512, Key Size 17', True, key)

  key.key_value = os.urandom(1020304)
  yield ('SHA512, Key Size 1020304', True, key)


def _proto_keys() -> Iterator[Tuple[str, bool, hmac_pb2.HmacKey]]:
  """Returns triples (name, validity, proto) for HmacKeys."""

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

  key = hmac_pb2.HmacKey(
      version=1,
      key_value=os.urandom(10),
      params=hmac_pb2.HmacParams(
          hash=common_pb2.HashType.SHA256, tag_size=10
      ),
  )
  yield ('Version 1 (invalid)', False, key)

  key = hmac_pb2.HmacKey(
      version=0,
      key_value=os.urandom(10),
  )
  yield ('Params not set (invalid)', False, key)


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
