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

"""Test keys for Composite ML-DSA."""

from typing import Iterator, Tuple

from tink.proto import composite_ml_dsa_pb2
from tink.proto import ecdsa_pb2
from tink.proto import ml_dsa_pb2
from tink.proto import tink_pb2
from cross_language import test_key
from cross_language.signature import ecdsa_keys
from cross_language.signature import ed25519_keys
from cross_language.signature import mldsa_keys

_PRIVATE_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.CompositeMlDsaPrivateKey'
)
_PUBLIC_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.CompositeMlDsaPublicKey'
)
_MLDSA_PRIVATE_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.MlDsaPrivateKey'
)
_MLDSA_PUBLIC_TYPE_URL = 'type.googleapis.com/google.crypto.tink.MlDsaPublicKey'


def _with_der_encoding(
    key: ecdsa_pb2.EcdsaPrivateKey,
) -> ecdsa_pb2.EcdsaPrivateKey:
  key.public_key.params.encoding = ecdsa_pb2.EcdsaSignatureEncoding.DER
  return key


def _make_composite_key_pair(
    ml_dsa_instance: ml_dsa_pb2.MlDsaInstance,
    classical_algorithm: composite_ml_dsa_pb2.CompositeMlDsaClassicalAlgorithm,
    mldsa_priv: ml_dsa_pb2.MlDsaPrivateKey,
    classical_type_url_prefix: str,
    classical_priv_bytes: bytes,
    classical_pub_bytes: bytes,
    version: int = 0,
) -> Tuple[
    composite_ml_dsa_pb2.CompositeMlDsaPrivateKey,
    composite_ml_dsa_pb2.CompositeMlDsaPublicKey,
]:
  """Constructs a (CompositeMlDsaPrivateKey, CompositeMlDsaPublicKey) pair."""
  params = composite_ml_dsa_pb2.CompositeMlDsaParams(
      ml_dsa_instance=ml_dsa_instance,
      classical_algorithm=classical_algorithm,
  )
  priv_key = composite_ml_dsa_pb2.CompositeMlDsaPrivateKey(
      version=version,
      params=params,
      ml_dsa_private_key=tink_pb2.KeyData(
          type_url=_MLDSA_PRIVATE_TYPE_URL,
          value=mldsa_priv.SerializeToString(),
          key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      ),
      classical_private_key=tink_pb2.KeyData(
          type_url=f'{classical_type_url_prefix}PrivateKey',
          value=classical_priv_bytes,
          key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
      ),
  )
  pub_key = composite_ml_dsa_pb2.CompositeMlDsaPublicKey(
      version=version,
      params=params,
      ml_dsa_public_key=tink_pb2.KeyData(
          type_url=_MLDSA_PUBLIC_TYPE_URL,
          value=mldsa_priv.public_key.SerializeToString(),
          key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      ),
      classical_public_key=tink_pb2.KeyData(
          type_url=f'{classical_type_url_prefix}PublicKey',
          value=classical_pub_bytes,
          key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
      ),
  )
  return (priv_key, pub_key)


def _test_key_pairs() -> Iterator[
    Tuple[
        str,
        bool,
        tink_pb2.OutputPrefixType,
        composite_ml_dsa_pb2.CompositeMlDsaPrivateKey,
        composite_ml_dsa_pb2.CompositeMlDsaPublicKey,
    ]
]:
  """Yields (name, valid, output_prefix_type, priv_proto, pub_proto) tuples."""
  mldsa44 = mldsa_keys.basic_p44_key()
  mldsa65 = mldsa_keys.basic_p65_key()
  mldsa87 = mldsa_keys.basic_p87_key()

  ed25519 = ed25519_keys.basic_ed25519_key()
  ecdsa_p256 = _with_der_encoding(ecdsa_keys.basic_p256_key())
  ecdsa_p384 = _with_der_encoding(ecdsa_keys.basic_p384_key())
  ecdsa_p521 = _with_der_encoding(ecdsa_keys.basic_p521_key())

  ed_prefix = 'type.googleapis.com/google.crypto.tink.Ed25519'
  ecdsa_prefix = 'type.googleapis.com/google.crypto.tink.Ecdsa'

  def _case(
      ml_dsa_instance: ml_dsa_pb2.MlDsaInstance,
      classical_algorithm: composite_ml_dsa_pb2.CompositeMlDsaClassicalAlgorithm,
      output_prefix_type: tink_pb2.OutputPrefixType,
      mldsa_key: ml_dsa_pb2.MlDsaPrivateKey,
      type_url_prefix: str,
      classical_key,
      valid: bool,
      version: int = 0,
  ):
    priv, pub = _make_composite_key_pair(
        ml_dsa_instance,
        classical_algorithm,
        mldsa_key,
        type_url_prefix,
        classical_key.SerializeToString(),
        classical_key.public_key.SerializeToString(),
        version=version,
    )
    name = 'CompositeMlDsaKey(%s,%s,%s,v=%d)' % (
        ml_dsa_pb2.MlDsaInstance.Name(ml_dsa_instance),
        composite_ml_dsa_pb2.CompositeMlDsaClassicalAlgorithm.Name(
            classical_algorithm
        ),
        tink_pb2.OutputPrefixType.Name(output_prefix_type),
        version,
    )
    return (name, valid, output_prefix_type, priv, pub)

  # Valid test cases (one per valid MlDsaInstance).
  yield _case(
      ml_dsa_pb2.ML_DSA_44,
      composite_ml_dsa_pb2.CLASSICAL_ALGORITHM_ECDSA_P256,
      tink_pb2.OutputPrefixType.TINK,
      mldsa44,
      ecdsa_prefix,
      ecdsa_p256,
      valid=True,
  )
  yield _case(
      ml_dsa_pb2.ML_DSA_65,
      composite_ml_dsa_pb2.CLASSICAL_ALGORITHM_ED25519,
      tink_pb2.OutputPrefixType.TINK,
      mldsa65,
      ed_prefix,
      ed25519,
      valid=True,
  )
  yield _case(
      ml_dsa_pb2.ML_DSA_87,
      composite_ml_dsa_pb2.CLASSICAL_ALGORITHM_ECDSA_P384,
      tink_pb2.OutputPrefixType.RAW,
      mldsa87,
      ecdsa_prefix,
      ecdsa_p384,
      valid=True,
  )
  # Invalid: ML_DSA_UNKNOWN_INSTANCE and LEGACY output prefix are not supported.
  yield _case(
      ml_dsa_pb2.ML_DSA_UNKNOWN_INSTANCE,
      composite_ml_dsa_pb2.CLASSICAL_ALGORITHM_ECDSA_P521,
      tink_pb2.OutputPrefixType.LEGACY,
      mldsa87,
      ecdsa_prefix,
      ecdsa_p521,
      valid=False,
  )
  # Invalid: CRUNCHY output prefix is not supported.
  yield _case(
      ml_dsa_pb2.ML_DSA_44,
      composite_ml_dsa_pb2.CLASSICAL_ALGORITHM_ECDSA_P256,
      tink_pb2.OutputPrefixType.CRUNCHY,
      mldsa44,
      ecdsa_prefix,
      ecdsa_p256,
      valid=False,
  )
  # Invalid: ECDSA_P521 is not compatible with ML_DSA_65.
  yield _case(
      ml_dsa_pb2.ML_DSA_65,
      composite_ml_dsa_pb2.CLASSICAL_ALGORITHM_ECDSA_P521,
      tink_pb2.OutputPrefixType.TINK,
      mldsa65,
      ecdsa_prefix,
      ecdsa_p521,
      valid=False,
  )
  # Invalid: version must be 0.
  yield _case(
      ml_dsa_pb2.ML_DSA_87,
      composite_ml_dsa_pb2.CLASSICAL_ALGORITHM_ECDSA_P384,
      tink_pb2.OutputPrefixType.RAW,
      mldsa87,
      ecdsa_prefix,
      ecdsa_p384,
      valid=False,
      version=1,
  )


def composite_mldsa_private_keys() -> Iterator[test_key.TestKey]:
  """Returns private test keys for Composite ML-DSA."""
  for name, valid, output_prefix_type, priv_proto, _ in _test_key_pairs():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PRIVATE_TYPE_URL,
        serialized_value=priv_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE,
        output_prefix_type=output_prefix_type,
        valid=valid,
    )


def composite_mldsa_public_keys() -> Iterator[test_key.TestKey]:
  """Returns public test keys for Composite ML-DSA."""
  for name, valid, output_prefix_type, _, pub_proto in _test_key_pairs():
    yield test_key.TestKey(
        test_name=name,
        type_url=_PUBLIC_TYPE_URL,
        serialized_value=pub_proto.SerializeToString(),
        key_material_type=tink_pb2.KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC,
        output_prefix_type=output_prefix_type,
        valid=valid,
    )
