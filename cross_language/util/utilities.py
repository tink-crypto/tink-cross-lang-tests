# Copyright 2020 Google LLC
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

"""Various utility functions for the cross language tests.
"""

from typing import Any, Iterable, List

from tink import aead
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead

from tink.proto import tink_pb2
import tink_config

# All languages supported by cross-language tests.
ALL_LANGUAGES = ['cc', 'java', 'go', 'python']


# For each KeyType, a list of Tinkey KeyTemplate names.
# TODO(juerg): Add missing key template names, and remove deprecated names.
# TODO(tholenst): Change this to a function
KEY_TEMPLATE_NAMES = {
    'AesEaxKey': [
        'AES128_EAX', 'AES128_EAX_RAW', 'AES256_EAX', 'AES256_EAX_RAW'
    ],
    'AesGcmKey': [
        'AES128_GCM', 'AES128_GCM_RAW', 'AES256_GCM', 'AES256_GCM_RAW'
    ],
    'AesGcmSivKey': [
        'AES128_GCM_SIV', 'AES128_GCM_SIV_RAW', 'AES256_GCM_SIV',
        'AES256_GCM_SIV_RAW'
    ],
    'AesCtrHmacAeadKey': [
        'AES128_CTR_HMAC_SHA256', 'AES128_CTR_HMAC_SHA256_RAW',
        'AES256_CTR_HMAC_SHA256', 'AES256_CTR_HMAC_SHA256_RAW'
    ],
    'ChaCha20Poly1305Key': ['CHACHA20_POLY1305', 'CHACHA20_POLY1305_RAW'],
    'XChaCha20Poly1305Key': ['XCHACHA20_POLY1305', 'XCHACHA20_POLY1305_RAW'],
    'KmsAeadKey': [],
    'KmsEnvelopeAeadKey': [],
    'AesSivKey': ['AES256_SIV'],
    'AesCtrHmacStreamingKey': [
        'AES128_CTR_HMAC_SHA256_4KB',
        'AES128_CTR_HMAC_SHA256_1MB',
        'AES256_CTR_HMAC_SHA256_4KB',
        'AES256_CTR_HMAC_SHA256_1MB',
    ],
    'AesGcmHkdfStreamingKey': [
        'AES128_GCM_HKDF_4KB',
        'AES128_GCM_HKDF_1MB',
        'AES256_GCM_HKDF_4KB',
        'AES256_GCM_HKDF_1MB',
    ],
    'EciesAeadHkdfPrivateKey': [
        'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM',
        'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM',
        'ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256',
        'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256',
    ],
    'HpkePrivateKey': [
        'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM',
        'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW',
        'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM',
        'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW',
        'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305',
        'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW',
    ],
    'AesCmacKey': ['AES_CMAC'],
    'HmacKey': [
        'HMAC_SHA256_128BITTAG', 'HMAC_SHA256_256BITTAG',
        'HMAC_SHA512_256BITTAG', 'HMAC_SHA512_512BITTAG'
    ],
    'EcdsaPrivateKey': [
        'ECDSA_P256', 'ECDSA_P256_RAW', 'ECDSA_P384', 'ECDSA_P384_SHA384',
        'ECDSA_P384_SHA512', 'ECDSA_P521', 'ECDSA_P256_IEEE_P1363',
        'ECDSA_P384_IEEE_P1363', 'ECDSA_P384_SHA384_IEEE_P1363',
        'ECDSA_P521_IEEE_P1363'
    ],
    'Ed25519PrivateKey': ['ED25519'],
    'RsaSsaPkcs1PrivateKey': [
        'RSA_SSA_PKCS1_3072_SHA256_F4', 'RSA_SSA_PKCS1_4096_SHA512_F4'
    ],
    'RsaSsaPssPrivateKey': [
        'RSA_SSA_PSS_3072_SHA256_SHA256_32_F4',
        'RSA_SSA_PSS_4096_SHA512_SHA512_64_F4'
    ],
    'AesCmacPrfKey': ['AES_CMAC_PRF'],
    'HmacPrfKey': ['HMAC_SHA256_PRF', 'HMAC_SHA512_PRF'],
    'HkdfPrfKey': ['HKDF_SHA256'],
    'JwtHmacKey': [
        'JWT_HS256', 'JWT_HS256_RAW', 'JWT_HS384', 'JWT_HS384_RAW', 'JWT_HS512',
        'JWT_HS512_RAW'
    ],
    'JwtEcdsaPrivateKey': [
        'JWT_ES256', 'JWT_ES256_RAW', 'JWT_ES384', 'JWT_ES384_RAW', 'JWT_ES512',
        'JWT_ES512_RAW'
    ],
    'JwtRsaSsaPkcs1PrivateKey': [
        'JWT_RS256_2048_F4', 'JWT_RS256_2048_F4_RAW', 'JWT_RS256_3072_F4',
        'JWT_RS256_3072_F4_RAW', 'JWT_RS384_3072_F4', 'JWT_RS384_3072_F4_RAW',
        'JWT_RS512_4096_F4', 'JWT_RS512_4096_F4_RAW'
    ],
    'JwtRsaSsaPssPrivateKey': [
        'JWT_PS256_2048_F4', 'JWT_PS256_2048_F4_RAW', 'JWT_PS256_3072_F4',
        'JWT_PS256_3072_F4_RAW', 'JWT_PS384_3072_F4', 'JWT_PS384_3072_F4_RAW',
        'JWT_PS512_4096_F4', 'JWT_PS512_4096_F4_RAW'
    ],
}

# KeyTemplate (as Protobuf) for each KeyTemplate name.
KEY_TEMPLATE = {
    'AES128_EAX':
        aead.aead_key_templates.AES128_EAX,
    'AES128_EAX_RAW':
        aead.aead_key_templates.AES128_EAX_RAW,
    'AES256_EAX':
        aead.aead_key_templates.AES256_EAX,
    'AES256_EAX_RAW':
        aead.aead_key_templates.AES256_EAX_RAW,
    'AES128_GCM':
        aead.aead_key_templates.AES128_GCM,
    'AES128_GCM_RAW':
        aead.aead_key_templates.AES128_GCM_RAW,
    'AES256_GCM':
        aead.aead_key_templates.AES256_GCM,
    'AES256_GCM_RAW':
        aead.aead_key_templates.AES256_GCM_RAW,
    'AES128_GCM_SIV':
        aead.aead_key_templates.AES128_GCM_SIV,
    'AES128_GCM_SIV_RAW':
        aead.aead_key_templates.AES128_GCM_SIV_RAW,
    'AES256_GCM_SIV':
        aead.aead_key_templates.AES256_GCM_SIV,
    'AES256_GCM_SIV_RAW':
        aead.aead_key_templates.AES256_GCM_SIV_RAW,
    'AES128_CTR_HMAC_SHA256':
        aead.aead_key_templates.AES128_CTR_HMAC_SHA256,
    'AES128_CTR_HMAC_SHA256_RAW':
        aead.aead_key_templates.AES128_CTR_HMAC_SHA256_RAW,
    'AES256_CTR_HMAC_SHA256':
        aead.aead_key_templates.AES256_CTR_HMAC_SHA256,
    'AES256_CTR_HMAC_SHA256_RAW':
        aead.aead_key_templates.AES256_CTR_HMAC_SHA256_RAW,
    'CHACHA20_POLY1305':
        tink_pb2.KeyTemplate(
            type_url=('type.googleapis.com/google.crypto.tink.' +
                      'ChaCha20Poly1305Key'),
            output_prefix_type=tink_pb2.TINK),
    'CHACHA20_POLY1305_RAW':
        tink_pb2.KeyTemplate(
            type_url=('type.googleapis.com/google.crypto.tink.' +
                      'ChaCha20Poly1305Key'),
            output_prefix_type=tink_pb2.RAW),
    'XCHACHA20_POLY1305':
        aead.aead_key_templates.XCHACHA20_POLY1305,
    'XCHACHA20_POLY1305_RAW':
        aead.aead_key_templates.XCHACHA20_POLY1305_RAW,
    'AES256_SIV':
        daead.deterministic_aead_key_templates.AES256_SIV,
    'AES128_CTR_HMAC_SHA256_4KB':
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB,
    'AES128_CTR_HMAC_SHA256_1MB':
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_1MB,
    'AES256_CTR_HMAC_SHA256_4KB':
        streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB,
    'AES256_CTR_HMAC_SHA256_1MB':
        streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_1MB,
    'AES128_GCM_HKDF_4KB':
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB,
    'AES128_GCM_HKDF_1MB':
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_1MB,
    'AES256_GCM_HKDF_4KB':
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_4KB,
    'AES256_GCM_HKDF_1MB':
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB,
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM':
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
    'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM':
        hybrid.hybrid_key_templates
        .ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM,
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256':
        hybrid.hybrid_key_templates
        .ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256,
    'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256':
        hybrid.hybrid_key_templates
        .ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256,
    'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM':
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM,
    'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW':
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW,
    'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM':
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
    'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW':
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW,
    'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305':
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
    'DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW':
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW,
    'AES_CMAC':
        mac.mac_key_templates.AES_CMAC,
    'HMAC_SHA256_128BITTAG':
        mac.mac_key_templates.HMAC_SHA256_128BITTAG,
    'HMAC_SHA256_256BITTAG':
        mac.mac_key_templates.HMAC_SHA256_256BITTAG,
    'HMAC_SHA512_256BITTAG':
        mac.mac_key_templates.HMAC_SHA512_256BITTAG,
    'HMAC_SHA512_512BITTAG':
        mac.mac_key_templates.HMAC_SHA512_512BITTAG,
    'ECDSA_P256':
        signature.signature_key_templates.ECDSA_P256,
    'ECDSA_P256_RAW':
        signature.signature_key_templates.ECDSA_P256_RAW,
    'ECDSA_P384':
        signature.signature_key_templates.ECDSA_P384,
    'ECDSA_P384_SHA384':
        signature.signature_key_templates.ECDSA_P384_SHA384,
    'ECDSA_P384_SHA512':
        signature.signature_key_templates.ECDSA_P384_SHA512,
    'ECDSA_P521':
        signature.signature_key_templates.ECDSA_P521,
    'ECDSA_P256_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P256_IEEE_P1363,
    'ECDSA_P384_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P384_IEEE_P1363,
    'ECDSA_P384_SHA384_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P384_SHA384_IEEE_P1363,
    'ECDSA_P521_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P521_IEEE_P1363,
    'ED25519':
        signature.signature_key_templates.ED25519,
    'RSA_SSA_PKCS1_3072_SHA256_F4':
        signature.signature_key_templates.RSA_SSA_PKCS1_3072_SHA256_F4,
    'RSA_SSA_PKCS1_4096_SHA512_F4':
        signature.signature_key_templates.RSA_SSA_PKCS1_4096_SHA512_F4,
    'RSA_SSA_PSS_3072_SHA256_SHA256_32_F4':
        signature.signature_key_templates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4,
    'RSA_SSA_PSS_4096_SHA512_SHA512_64_F4':
        signature.signature_key_templates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4,
    'AES_CMAC_PRF':
        prf.prf_key_templates.AES_CMAC,
    'HMAC_SHA256_PRF':
        prf.prf_key_templates.HMAC_SHA256,
    'HMAC_SHA512_PRF':
        prf.prf_key_templates.HMAC_SHA512,
    'HKDF_SHA256':
        prf.prf_key_templates.HKDF_SHA256,
    'JWT_HS256':
        jwt.jwt_hs256_template(),
    'JWT_HS256_RAW':
        jwt.raw_jwt_hs256_template(),
    'JWT_HS384':
        jwt.jwt_hs384_template(),
    'JWT_HS384_RAW':
        jwt.raw_jwt_hs384_template(),
    'JWT_HS512':
        jwt.jwt_hs512_template(),
    'JWT_HS512_RAW':
        jwt.raw_jwt_hs512_template(),
    'JWT_ES256':
        jwt.jwt_es256_template(),
    'JWT_ES256_RAW':
        jwt.raw_jwt_es256_template(),
    'JWT_ES384':
        jwt.jwt_es384_template(),
    'JWT_ES384_RAW':
        jwt.raw_jwt_es384_template(),
    'JWT_ES512':
        jwt.jwt_es512_template(),
    'JWT_ES512_RAW':
        jwt.raw_jwt_es512_template(),
    'JWT_RS256_2048_F4':
        jwt.jwt_rs256_2048_f4_template(),
    'JWT_RS256_2048_F4_RAW':
        jwt.raw_jwt_rs256_2048_f4_template(),
    'JWT_RS256_3072_F4':
        jwt.jwt_rs256_3072_f4_template(),
    'JWT_RS256_3072_F4_RAW':
        jwt.raw_jwt_rs256_3072_f4_template(),
    'JWT_RS384_3072_F4':
        jwt.jwt_rs384_3072_f4_template(),
    'JWT_RS384_3072_F4_RAW':
        jwt.raw_jwt_rs384_3072_f4_template(),
    'JWT_RS512_4096_F4':
        jwt.jwt_rs512_4096_f4_template(),
    'JWT_RS512_4096_F4_RAW':
        jwt.raw_jwt_rs512_4096_f4_template(),
    'JWT_PS256_2048_F4':
        jwt.jwt_ps256_2048_f4_template(),
    'JWT_PS256_2048_F4_RAW':
        jwt.raw_jwt_ps256_2048_f4_template(),
    'JWT_PS256_3072_F4':
        jwt.jwt_ps256_3072_f4_template(),
    'JWT_PS256_3072_F4_RAW':
        jwt.raw_jwt_ps256_3072_f4_template(),
    'JWT_PS384_3072_F4':
        jwt.jwt_ps384_3072_f4_template(),
    'JWT_PS384_3072_F4_RAW':
        jwt.raw_jwt_ps384_3072_f4_template(),
    'JWT_PS512_4096_F4':
        jwt.jwt_ps512_4096_f4_template(),
    'JWT_PS512_4096_F4_RAW':
        jwt.raw_jwt_ps512_4096_f4_template(),
}


# Key template names for which the list of supported languages is different from
# the list of supported languages of the whole key type.
_CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME = {
    # currently empty.
}


def _supported_languages_by_template(
    template_name: str, key_type: str) -> List[str]:
  if template_name in _CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME:
    return _CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[template_name]
  return tink_config.supported_languages_for_key_type(key_type)


def _all_key_template_names_with_key_type():
  for key_type, template_names in KEY_TEMPLATE_NAMES.items():
    for template_name in template_names:
      yield (template_name, key_type)


def tinkey_template_names_for(primitive_class: Any) -> Iterable[str]:
  """Returns all the key template names for the given primitive type."""
  for key_type in tink_config.key_types_for_primitive(primitive_class):
    for template_name in KEY_TEMPLATE_NAMES[key_type]:
      yield template_name


SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME = {
    name: _supported_languages_by_template(name, template)
    for name, template in _all_key_template_names_with_key_type()
}


def key_types_in_keyset(keyset: bytes) -> List[str]:
  """Returns a list containing all key types in a keyset, in order."""
  parsed_keyset = tink_pb2.Keyset.FromString(keyset)
  type_urls = [k.key_data.type_url for k in parsed_keyset.key]
  return [tink_config.key_type_from_type_url(t) for t in type_urls]
