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

from collections.abc import Iterable
import os
from typing import Iterator, Tuple

from tink.proto import common_pb2
from tink.proto import hmac_pb2


def _valid_hmac_keys_no_type_url() -> Iterable[hmac_pb2.HmacKey]:
  return [
      # Try SHA1 tag sizes
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=15
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=20
          ),
      ),
      # Try SHA1 key sizes
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(17),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(30),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      # Very large key
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(1274),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      # Different hash functions, min tag & key size.
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA224, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA256, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA384, tag_size=10
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA512, tag_size=10
          ),
      ),
  ]


def valid_hmac_keys() -> Iterator[Tuple[str, bytes]]:
  """Returns pairs (type_url, value) for valid HMAC keys (as in KeyData)."""
  for msg in _valid_hmac_keys_no_type_url():
    yield (
        'type.googleapis.com/google.crypto.tink.HmacKey',
        msg.SerializeToString(),
    )


def _invalid_hmac_keys_no_type_url() -> Iterable[hmac_pb2.HmacKey]:
  """Returns a list of HmacKeys which Tink considers invalid."""
  return [
      # Short key size
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(15),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=10
          ),
      ),
      # Too short tag
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(hash=common_pb2.HashType.SHA1, tag_size=9),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA224, tag_size=9
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA256, tag_size=9
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA384, tag_size=9
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA512, tag_size=9
          ),
      ),
      # Too long tag
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA1, tag_size=21
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA224, tag_size=29
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA256, tag_size=33
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA384, tag_size=49
          ),
      ),
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
          params=hmac_pb2.HmacParams(
              hash=common_pb2.HashType.SHA512, tag_size=65
          ),
      ),
      # Params not set
      hmac_pb2.HmacKey(
          version=0,
          key_value=os.urandom(16),
      ),
  ]


def invalid_hmac_keys() -> Iterator[Tuple[str, bytes]]:
  """Returns pairs (type_url, value) for invalid HMAC keys (as in KeyData)."""
  for msg in _invalid_hmac_keys_no_type_url():
    yield (
        'type.googleapis.com/google.crypto.tink.HmacKey',
        msg.SerializeToString(),
    )
  # Proto-Unparseable value
  yield (
      'type.googleapis.com/google.crypto.tink.HmacKey',
      b'\x80',
  )
