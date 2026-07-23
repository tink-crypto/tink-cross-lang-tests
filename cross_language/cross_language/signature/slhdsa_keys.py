# Copyright 2026 Google LLC
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

"""Test keys for SLH-DSA."""

import binascii
import dataclasses
from typing import Iterator, Tuple

from tink.proto import slh_dsa_pb2
from tink.proto import tink_pb2
from cross_language import test_key

_PRIVATE_TYPE_URL = 'type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey'
_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.SlhDsaPublicKey'


@dataclasses.dataclass(frozen=True)
class _TestVector:
  name: str
  valid: bool
  key_proto: slh_dsa_pb2.SlhDsaPrivateKey


# Test vectors from Go implementation (key_pairs_test.go).
# Currently only SLH-DSA-SHA2-128s is consistently supported among all
# Tink languages.
def _proto_keys() -> Iterator[_TestVector]:
  yield _TestVector(
      'SLH_DSA_SHA2_128s',
      True,
      slh_dsa_pb2.SlhDsaPrivateKey(
          version=0,
          key_value=binascii.unhexlify(
              'd44f6f06a73a07451096ad4bfbd240cb54b779330a65ed34ec0cd372c96fe48bf2b907c6b73d52125c3930a195ef650baf7f68a07f4f3435408ac5ecaafaf4f3'
          ),
          public_key=slh_dsa_pb2.SlhDsaPublicKey(
              version=0,
              params=slh_dsa_pb2.SlhDsaParams(
                  hash_type=slh_dsa_pb2.SHA2,
                  key_size=64,
                  sig_type=slh_dsa_pb2.SMALL_SIGNATURE,
              ),
              key_value=binascii.unhexlify(
                  'f2b907c6b73d52125c3930a195ef650baf7f68a07f4f3435408ac5ecaafaf4f3'
              ),
          ),
      ),
  )


def _output_prefix_types() -> Iterator[Tuple[tink_pb2.OutputPrefixType, bool]]:
  yield (tink_pb2.OutputPrefixType.UNKNOWN_PREFIX, False)
  yield (tink_pb2.OutputPrefixType.TINK, True)
  yield (tink_pb2.OutputPrefixType.LEGACY, False)
  yield (tink_pb2.OutputPrefixType.CRUNCHY, False)
  yield (tink_pb2.OutputPrefixType.RAW, True)


def slhdsa_private_keys() -> Iterator[test_key.TestKey]:
  """Returns private test keys for SLH-DSA."""
  for vector in _proto_keys():
    yield test_key.TestKey(
        test_name=vector.name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=vector.key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=vector.valid,
    )

  # Pick first valid key for output prefix tests
  basic_key = next(_proto_keys()).key_proto
  for output_prefix_type, valid in _output_prefix_types():
    output_prefix_type_name = tink_pb2.OutputPrefixType.Name(output_prefix_type)
    yield test_key.TestKey(
        test_name=f'OutputPrefixType={output_prefix_type_name}',
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=basic_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        output_prefix_type=output_prefix_type,
        valid=valid,
    )


def slhdsa_public_keys() -> Iterator[test_key.TestKey]:
  """Returns public test keys for SLH-DSA."""
  for vector in _proto_keys():
    yield test_key.TestKey(
        test_name=vector.name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=vector.key_proto.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        valid=vector.valid,
    )

  basic_key = next(_proto_keys()).key_proto
  for output_prefix_type, valid in _output_prefix_types():
    output_prefix_type_name = tink_pb2.OutputPrefixType.Name(output_prefix_type)
    yield test_key.TestKey(
        test_name=f'OutputPrefixType={output_prefix_type_name}',
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=basic_key.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        output_prefix_type=output_prefix_type,
        valid=valid,
    )
