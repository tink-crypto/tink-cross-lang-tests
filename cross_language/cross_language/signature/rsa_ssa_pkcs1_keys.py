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

"""Test keys for RsaSsaPkcs1."""

import base64
from typing import Iterator, Tuple

from tink.proto import common_pb2
from tink.proto import rsa_ssa_pkcs1_pb2
from tink.proto import tink_pb2
from cross_language import test_key


_PRIVATE_TYPE_URL = 'type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey'
_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey'


def _base64_decode(s: str) -> bytes:
  # Python requires correct padding, but ignores everything after the correct
  # padding. Hence we just add enough padding to make it always work.
  return base64.urlsafe_b64decode(s + '===')


def _basic_2048bit_key() -> rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PrivateKey:
  """Key from https://www.rfc-editor.org/rfc/rfc7517#appendix-C."""

  key = rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PrivateKey(
      version=0,
      public_key=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
          version=0,
          params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
              hash_type=common_pb2.HashType.SHA256,
          ),
          n=_base64_decode("""
            t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRy
            O125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP
            8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0
            Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0X
            OC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1
            _I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q
            """),
          e=_base64_decode('AQAB'),
      ),
      d=_base64_decode("""
            GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS
            NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U
            vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu
            ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu
            rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a
            hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ
            """),
      p=_base64_decode("""
            2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf
            QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8
            UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws
            """),
      q=_base64_decode("""
            1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6I
            edis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYK
            rYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s
            """),
      dp=_base64_decode("""
            KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3
            tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1w
            Y52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c
            """),
      dq=_base64_decode("""
            AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9
            GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy
            mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots
            """),
      crt=_base64_decode("""
            lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq
            abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o
            Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8
            """),
  )
  assert len(key.public_key.n) == 2048/8
  return key


def _to_bytes(i: int) -> bytes:
  return i.to_bytes((i.bit_length() + 7) // 8, 'big')


def _key_with_p_and_q(
    p: int, q: int
) -> rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PrivateKey:
  """Creates a key from two primes p and q (without checking validity)."""

  n = p * q
  e = 65537
  phi = (p-1) * (q-1)
  d = pow(e, -1, phi)
  dp = d % (p-1)
  dq = d % (q-1)
  crt = pow(q, -1, p)
  return rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PrivateKey(
      version=0,
      public_key=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PublicKey(
          version=0,
          params=rsa_ssa_pkcs1_pb2.RsaSsaPkcs1Params(
              hash_type=common_pb2.HashType.SHA256,
          ),
          n=_to_bytes(n),
          e=_to_bytes(e),
      ),
      d=_to_bytes(d),
      p=_to_bytes(p),
      q=_to_bytes(q),
      dp=_to_bytes(dp),
      dq=_to_bytes(dq),
      crt=_to_bytes(crt),
  )


## Some primes:
## (2 << 1023) + [1155, 1493, 1583, 1685, 1863]
## (2 << 1024) - [105, 179, 1397, 3177, 5025]
def _keys_close_to_2048_bit_threshold() -> (
    Iterator[Tuple[str, bool, rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PrivateKey]]
):
  """Yields triples with p * q close to 2^2047.

  Note that 2^2047 is the smallest number which needs 2048 bits.
  """

  p = (1 << 1024) - 3177
  q1 = (1 << 1023) + 1155
  q2 = (1 << 1023) + 1863
  # p * q1 = (2^2047 - 3177 * 2^1023 + 2 * 1155 * 2^1023 - 3177*1155)
  yield('2047 bit key', False, _key_with_p_and_q(p, q1))
  # p * q1 = (2^2047 - 3177 * 2^1023 + 2 * 1863 * 2^1023 - 3177*1863)
  yield('2048 bit key', True, _key_with_p_and_q(p, q2))


def _proto_keys() -> (
    Iterator[Tuple[str, bool, rsa_ssa_pkcs1_pb2.RsaSsaPkcs1PrivateKey]]
):
  """Yields triples (name, validity, proto) for RsaSsaPkcs1PrivateKey."""

  key_proto = _basic_2048bit_key()
  yield ('Basic 2048 bit key', True, key_proto)

  for triple in _keys_close_to_2048_bit_threshold():
    yield triple


def rsa_ssa_pkcs1_private_keys() -> Iterator[test_key.TestKey]:
  """Returns private test keys for RsaSsaPkcs1."""

  for (name, valid, key_proto) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=key_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        valid=valid,
    )


def rsa_ssa_pkcs1_public_keys() -> Iterator[test_key.TestKey]:
  """Returns public test keys for RsaSsaPkcs1."""

  for (name, valid, key_proto) in _proto_keys():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=key_proto.public_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        valid=valid,
    )
