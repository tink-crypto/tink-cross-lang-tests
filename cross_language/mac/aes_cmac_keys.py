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

from collections.abc import Iterable
import os
from typing import Iterator, Tuple

from tink.proto import aes_cmac_pb2


def _valid_aes_cmac_keys_no_type_url() -> Iterable[aes_cmac_pb2.AesCmacKey]:
  return [
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=10),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=11),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=12),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=13),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=14),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=15),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=16),
      ),
  ]


def valid_aes_cmac_keys() -> Iterator[Tuple[str, bytes]]:
  """Returns pairs (type_url, value) for valid HMAC keys (as in KeyData)."""
  for msg in _valid_aes_cmac_keys_no_type_url():
    yield (
        'type.googleapis.com/google.crypto.tink.AesCmacKey',
        msg.SerializeToString(),
    )


def _invalid_aes_cmac_keys_no_type_url() -> Iterable[aes_cmac_pb2.AesCmacKey]:
  """Returns a list of AesCmacKeys which Tink considers invalid."""
  return [
      # Wrong key length
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(16),
          params=aes_cmac_pb2.AesCmacParams(tag_size=16),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(24),
          params=aes_cmac_pb2.AesCmacParams(tag_size=16),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(31),
          params=aes_cmac_pb2.AesCmacParams(tag_size=16),
      ),
      # Wrong tag length
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=17),
      ),
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=9),
      ),
      # Params not set
      aes_cmac_pb2.AesCmacKey(
          version=0,
          key_value=os.urandom(16),
      ),
      # Wrong version
      aes_cmac_pb2.AesCmacKey(
          version=1,
          key_value=os.urandom(32),
          params=aes_cmac_pb2.AesCmacParams(tag_size=16),
      ),
  ]


def invalid_aes_cmac_keys() -> Iterator[Tuple[str, bytes]]:
  """Returns pairs (type_url, value) for invalid AES CMAC keys (as in KeyData)."""
  for msg in _invalid_aes_cmac_keys_no_type_url():
    yield (
        'type.googleapis.com/google.crypto.tink.AesCmacKey',
        msg.SerializeToString(),
    )
  # Proto-Unparseable value
  yield (
      'type.googleapis.com/google.crypto.tink.AesCmacKey',
      b'\x80',
  )
