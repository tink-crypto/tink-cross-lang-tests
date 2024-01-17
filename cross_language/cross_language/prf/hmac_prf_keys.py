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

"""Test keys for HMAC PRF."""

import os
from typing import Iterator, Tuple

from tink.proto import common_pb2
from tink.proto import hmac_prf_pb2
from tink.proto import tink_pb2
from cross_language import test_key


def _basic_key() -> hmac_prf_pb2.HmacPrfKey:
  return hmac_prf_pb2.HmacPrfKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_prf_pb2.HmacPrfParams(hash=common_pb2.HashType.SHA1),
  )


def _proto_keys_() -> Iterator[Tuple[str, bool, hmac_prf_pb2.HmacPrfKey]]:
  """Returns triples (name, validity, proto) for HmacPrfKey, HashType=SHA1."""

  key = hmac_prf_pb2.HmacPrfKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_prf_pb2.HmacPrfParams(hash=common_pb2.HashType.SHA1),
  )
  yield ('SHA1 key', True, key)

  key = hmac_prf_pb2.HmacPrfKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_prf_pb2.HmacPrfParams(hash=common_pb2.HashType.SHA256),
  )
  yield ('SHA256 key', True, key)


def _b315441300_keys() -> Iterator[Tuple[str, bool, hmac_prf_pb2.HmacPrfKey]]:
  """Yields triples (name, validity, proto) which fall under b/315441300.

  Description of this bug: Trying to compute the HMacPrf with SHA224 or SHA384
  in Python or C++ currently fails with:
  "PRF only supports outputs up to 0 bytes, but 16 bytes were requested."
  """

  key = hmac_prf_pb2.HmacPrfKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_prf_pb2.HmacPrfParams(hash=common_pb2.HashType.SHA224),
  )
  yield ('SHA224 key', True, key)

  key = hmac_prf_pb2.HmacPrfKey(
      version=0,
      key_value=os.urandom(16),
      params=hmac_prf_pb2.HmacPrfParams(hash=common_pb2.HashType.SHA384),
  )
  yield ('SHA384 key', True, key)


def hmac_prf_keys() -> Iterator[test_key.TestKey]:
  """Returns test keys for HMac."""
  for (name, valid, msg) in _proto_keys_():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.HmacPrfKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        output_prefix_type=tink_pb2.OutputPrefixType.RAW,
        valid=valid,
    )
  for (name, valid, msg) in _b315441300_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url='type.googleapis.com/google.crypto.tink.HmacPrfKey',
        serialized_value=msg.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        output_prefix_type=tink_pb2.OutputPrefixType.RAW,
        valid=valid,
        tags=['b/315441300']
    )
  # For PRF Keys, only output prefix RAW is accepted.
  yield test_key.TestKey(
      test_name='TINK key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.HmacPrfKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.TINK,
      valid=False,
  )
  yield test_key.TestKey(
      test_name='CRUNCHY key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.HmacPrfKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.CRUNCHY,
      valid=False,
  )
  yield test_key.TestKey(
      test_name='LEGACY key (invalid)',
      type_url='type.googleapis.com/google.crypto.tink.HmacPrfKey',
      serialized_value=_basic_key().SerializeToString(),
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.LEGACY,
      valid=False,
  )
  # Proto-Unparseable value
  yield test_key.TestKey(
      test_name='Invalid proto-unparseable value',
      type_url='type.googleapis.com/google.crypto.tink.HmacPrfKey',
      serialized_value=b'\x80',
      key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
      output_prefix_type=tink_pb2.OutputPrefixType.RAW,
      valid=False,
  )
