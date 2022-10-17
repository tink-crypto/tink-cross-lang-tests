# Copyright 2021 Google LLC
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
"""Cross-language tests for the "kid" header set by JWT primitives."""

import base64
import json
from typing import Optional

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import jwt

from tink.proto import jwt_ecdsa_pb2
from tink.proto import jwt_hmac_pb2
from tink.proto import jwt_rsa_ssa_pkcs1_pb2
from tink.proto import jwt_rsa_ssa_pss_pb2
from tink.proto import tink_pb2
from util import testing_servers
from util import utilities

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['jwt']


def setUpModule():
  jwt.register_jwt_mac()
  jwt.register_jwt_signature()
  testing_servers.start('jwt')


def tearDownModule():
  testing_servers.stop()


def base64_decode(encoded_data: bytes) -> bytes:
  padded_encoded_data = encoded_data + b'==='
  return base64.urlsafe_b64decode(padded_encoded_data)


def decode_kid(compact: str) -> Optional[str]:
  encoded_header, _, _ = compact.encode('utf8').split(b'.')
  json_header = base64_decode(encoded_header)
  header = json.loads(json_header)
  return header.get('kid', None)


def generate_jwt_mac_keyset_with_custom_kid(
    template_name: str, custom_kid: str) -> tink_pb2.Keyset:
  key_template = utilities.KEY_TEMPLATE[template_name]
  keyset_handle = tink.new_keyset_handle(key_template)
  # parse key_data.value, set custom_kid and serialize
  key_data_value = keyset_handle._keyset.key[0].key_data.value
  if template_name.startswith('JWT_HS256'):
    hmac_key = jwt_hmac_pb2.JwtHmacKey.FromString(key_data_value)
    hmac_key.custom_kid.value = custom_kid
    key_data_value = hmac_key.SerializeToString()
  else:
    raise ValueError('unknown alg')
  keyset_handle._keyset.key[0].key_data.value = key_data_value
  return keyset_handle._keyset


def generate_jwt_signature_keyset_with_custom_kid(
    template_name: str, custom_kid: str) -> tink_pb2.Keyset:
  key_template = utilities.KEY_TEMPLATE[template_name]
  keyset_handle = tink.new_keyset_handle(key_template)
  # parse key_data.value, set custom_kid and serialize
  key_data_value = keyset_handle._keyset.key[0].key_data.value
  if template_name.startswith('JWT_ES256'):
    private_key = jwt_ecdsa_pb2.JwtEcdsaPrivateKey.FromString(key_data_value)
    private_key.public_key.custom_kid.value = custom_kid
    key_data_value = private_key.SerializeToString()
  elif template_name.startswith('JWT_RS256'):
    private_key = jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PrivateKey.FromString(
        key_data_value)
    private_key.public_key.custom_kid.value = custom_kid
    key_data_value = private_key.SerializeToString()
  elif template_name.startswith('JWT_PS256'):
    private_key = jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPrivateKey.FromString(
        key_data_value)
    private_key.public_key.custom_kid.value = custom_kid
    key_data_value = private_key.SerializeToString()
  else:
    raise ValueError('unknown template name')
  keyset_handle._keyset.key[0].key_data.value = key_data_value
  keyset = keyset_handle._keyset
  return keyset


class JwtKidTest(parameterized.TestCase):
  """Tests that all JWT primitives consistently add a "kid" header to tokens."""

  @parameterized.parameters(['JWT_HS256'])
  def test_jwt_mac_sets_kid_for_tink_templates(self, template_name):
    key_template = utilities.KEY_TEMPLATE[template_name]
    keyset = testing_servers.new_keyset('cc', key_template)
    raw_jwt = jwt.new_raw_jwt(without_expiration=True)
    for lang in SUPPORTED_LANGUAGES:
      jwt_mac = testing_servers.remote_primitive(lang, keyset, jwt.JwtMac)
      compact = jwt_mac.compute_mac_and_encode(raw_jwt)
      self.assertIsNotNone(decode_kid(compact))

  @parameterized.parameters(['JWT_HS256_RAW'])
  def test_jwt_mac_does_not_sets_kid_for_raw_templates(self, template_name):
    key_template = utilities.KEY_TEMPLATE[template_name]
    keyset = testing_servers.new_keyset('cc', key_template)
    raw_jwt = jwt.new_raw_jwt(without_expiration=True)
    for lang in SUPPORTED_LANGUAGES:
      jwt_mac = testing_servers.remote_primitive(lang, keyset, jwt.JwtMac)
      compact = jwt_mac.compute_mac_and_encode(raw_jwt)
      self.assertIsNone(decode_kid(compact))

  @parameterized.parameters(
      ['JWT_ES256', 'JWT_RS256_2048_F4', 'JWT_PS256_2048_F4'])
  def test_jwt_public_key_sign_sets_kid_for_tink_templates(self, template_name):
    key_template = utilities.KEY_TEMPLATE[template_name]
    keyset = testing_servers.new_keyset('cc', key_template)
    raw_jwt = jwt.new_raw_jwt(without_expiration=True)
    supported_langs = utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        template_name]
    for lang in supported_langs:
      jwt_sign = testing_servers.remote_primitive(lang, keyset,
                                                  jwt.JwtPublicKeySign)
      compact = jwt_sign.sign_and_encode(raw_jwt)
      self.assertIsNotNone(decode_kid(compact))

  @parameterized.parameters(
      ['JWT_ES256_RAW', 'JWT_RS256_2048_F4_RAW', 'JWT_PS256_2048_F4_RAW'])
  def test_jwt_public_key_sign_does_not_sets_kid_for_raw_templates(
      self, template_name):
    key_template = utilities.KEY_TEMPLATE[template_name]
    keyset = testing_servers.new_keyset('cc', key_template)
    raw_jwt = jwt.new_raw_jwt(without_expiration=True)
    supported_langs = utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        template_name]
    for lang in supported_langs:
      jwt_sign = testing_servers.remote_primitive(lang, keyset,
                                                  jwt.JwtPublicKeySign)
      compact = jwt_sign.sign_and_encode(raw_jwt)
      self.assertIsNone(decode_kid(compact))

  @parameterized.parameters(['JWT_HS256_RAW'])
  def test_jwt_mac_sets_custom_kid_for_raw_keys(self, template_name):
    keyset = generate_jwt_mac_keyset_with_custom_kid(
        template_name=template_name, custom_kid='my kid')
    raw_jwt = jwt.new_raw_jwt(without_expiration=True)
    for lang in SUPPORTED_LANGUAGES:
      jwt_mac = testing_servers.remote_primitive(lang,
                                                 keyset.SerializeToString(),
                                                 jwt.JwtMac)
      compact = jwt_mac.compute_mac_and_encode(raw_jwt)
      self.assertEqual(decode_kid(compact), 'my kid')

  @parameterized.parameters(['JWT_HS256'])
  def test_jwt_mac_fails_for_tink_keys_with_custom_kid(self, template_name):
    keyset = generate_jwt_mac_keyset_with_custom_kid(
        template_name=template_name, custom_kid='my kid')
    raw_jwt = jwt.new_raw_jwt(without_expiration=True)
    for lang in SUPPORTED_LANGUAGES:
      with self.assertRaises(
          tink.TinkError,
          msg=('%s supports JWT mac keys with TINK output prefix type '
               'and custom_kid set unexpectedly') % lang):
        jwt_mac = testing_servers.remote_primitive(lang,
                                                   keyset.SerializeToString(),
                                                   jwt.JwtMac)
        jwt_mac.compute_mac_and_encode(raw_jwt)

  @parameterized.parameters(
      ['JWT_ES256_RAW', 'JWT_RS256_2048_F4_RAW', 'JWT_PS256_2048_F4_RAW'])
  def test_jwt_public_key_sign_sets_custom_kid_for_raw_keys(
      self, template_name):
    keyset = generate_jwt_signature_keyset_with_custom_kid(
        template_name=template_name, custom_kid='my kid')
    raw_jwt = jwt.new_raw_jwt(without_expiration=True)
    supported_langs = utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        template_name]
    for lang in supported_langs:
      jwt_sign = testing_servers.remote_primitive(lang,
                                                  keyset.SerializeToString(),
                                                  jwt.JwtPublicKeySign)
      compact = jwt_sign.sign_and_encode(raw_jwt)
      self.assertEqual(decode_kid(compact), 'my kid')

  @parameterized.parameters(
      ['JWT_ES256', 'JWT_RS256_2048_F4', 'JWT_PS256_2048_F4'])
  def test_jwt_public_key_sign_fails_for_tink_keys_with_custom_kid(
      self, template_name):
    keyset = generate_jwt_signature_keyset_with_custom_kid(
        template_name=template_name, custom_kid='my kid')
    raw_jwt = jwt.new_raw_jwt(without_expiration=True)
    for lang in SUPPORTED_LANGUAGES:
      with self.assertRaises(
          tink.TinkError,
          msg=('%s supports JWT signature keys with TINK output prefix type '
               'and custom_kid set unexpectedly') % lang):
        jwt_sign = testing_servers.remote_primitive(lang,
                                                    keyset.SerializeToString(),
                                                    jwt.JwtPublicKeySign)
        jwt_sign.sign_and_encode(raw_jwt)


if __name__ == '__main__':
  absltest.main()
