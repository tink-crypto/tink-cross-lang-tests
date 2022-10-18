# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for tink.testing.cross_language.util.testing_server."""

import datetime
import io
import textwrap
from typing import Iterable, Tuple

from absl import flags
from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead

from tink.proto import tink_pb2
from util import key_util
from util import test_keys
from util import testing_servers

_SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE

_HEX_TEMPLATE = flags.DEFINE_string(
    'hex_template',
    aead.aead_key_templates.AES256_GCM.SerializeToString().hex(),
    'The template in hex format to use in the create_keyset test.'
)

_FORCE_FAILURE_FOR_ADDING_KEY_TO_DB = flags.DEFINE_boolean(
    'force_failure_for_adding_key_to_db', False,
    'Set to force a message which helps to add a new key to the DB.')

_MESSAGE_TEMPLATE = '''
Please add the following to _test_keys_db.py:
COPY PASTE START ===============================================================
db.add_key(
    template=r"""
{template_text_format}""",
    key=r"""
{key_text_format}""")
COPY PASTE END =================================================================
'''


def setUpModule():
  aead.register()
  daead.register()
  hybrid.register()
  jwt.register_jwt_mac()
  jwt.register_jwt_signature()
  mac.register()
  prf.register()
  signature.register()
  streaming_aead.register()


class TestingServersConfigTest(absltest.TestCase):

  def test_primitives(self):
    self.assertEqual(
        testing_servers._PRIMITIVE_STUBS.keys(),
        _SUPPORTED_LANGUAGES.keys(),
        msg=(
            'The primitives specified as keys in '
            'testing_servers._PRIMITIVE_STUBS must match the primitives '
            ' specified as keys in '
            'testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE.'
        ))

  def test_languages(self):
    for primitive in _SUPPORTED_LANGUAGES:
      languages = set(testing_servers.LANGUAGES)
      supported_languages = set(_SUPPORTED_LANGUAGES[primitive])
      self.assertContainsSubset(supported_languages, languages, msg=(
          'The languages specified in '
          'testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE must be a subset '
          'of the languages specified in testing_servers.LANGUAGES.'
      ))


def encrypted_keyset_test_cases() -> Iterable[Tuple[str, str, str]]:
  for lang in testing_servers.LANGUAGES:
    for reader_type, writer_type in testing_servers.KEYSET_READER_WRITER_TYPES:
      yield (lang, reader_type, writer_type)


class TestingServersTest(parameterized.TestCase):

  @classmethod
  def setUpClass(cls):
    super(TestingServersTest, cls).setUpClass()
    testing_servers.start('testing_server')

  @classmethod
  def tearDownClass(cls):
    testing_servers.stop()
    super(TestingServersTest, cls).tearDownClass()

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_get_template(self, lang):
    template = testing_servers.key_template(lang, 'AES128_GCM')
    self.assertEqual(template.type_url,
                     'type.googleapis.com/google.crypto.tink.AesGcmKey')

  @parameterized.parameters(testing_servers.LANGUAGES)
  def test_new_keyset(self, lang):
    """Tests that we can create a new keyset in each language.

    This test also serves to add new keys to the _test_keys_db -- see the
    comments there.

    Args:
      lang: language to use for the test
    """
    template = tink_pb2.KeyTemplate().FromString(
        bytes.fromhex(_HEX_TEMPLATE.value))
    keyset = testing_servers.new_keyset(lang, template)
    parsed_keyset = tink_pb2.Keyset.FromString(keyset)
    self.assertLen(parsed_keyset.key, 1)
    if _FORCE_FAILURE_FOR_ADDING_KEY_TO_DB.value:
      self.fail(
          _MESSAGE_TEMPLATE.format(
              template_text_format=textwrap.indent(
                  key_util.text_format(template), ' ' * 6),
              key_text_format=textwrap.indent(
                  key_util.text_format(parsed_keyset.key[0]), ' ' * 6)))

  @parameterized.parameters([
      aead.Aead, daead.DeterministicAead, streaming_aead.StreamingAead,
      hybrid.HybridDecrypt, hybrid.HybridEncrypt, mac.Mac,
      signature.PublicKeySign, signature.PublicKeyVerify, prf.PrfSet,
      jwt.JwtMac, jwt.JwtPublicKeySign, jwt.JwtPublicKeyVerify
  ])
  def test_create_with_correct_keyset(self, primitive):
    keyset = test_keys.some_keyset_for_primitive(primitive)
    _ = testing_servers.remote_primitive('python', keyset, primitive)

  @parameterized.parameters([
      aead.Aead, daead.DeterministicAead, streaming_aead.StreamingAead,
      hybrid.HybridDecrypt, hybrid.HybridEncrypt, mac.Mac,
      signature.PublicKeySign, signature.PublicKeyVerify, prf.PrfSet,
      jwt.JwtMac, jwt.JwtPublicKeySign, jwt.JwtPublicKeyVerify
  ])
  def test_create_with_incorrect_keyset(self, primitive):
    wrong_primitive = aead.Aead if primitive == mac.Mac else mac.Mac
    keyset = test_keys.some_keyset_for_primitive(wrong_primitive)
    with self.assertRaises(tink.TinkError):
      testing_servers.remote_primitive('python', keyset, primitive)

  @parameterized.parameters(encrypted_keyset_test_cases())
  def test_read_write_encrypted_keyset(self, lang, keyset_reader_type,
                                       keyset_writer_type):
    keyset = testing_servers.new_keyset(lang,
                                        aead.aead_key_templates.AES128_GCM)
    master_keyset = testing_servers.new_keyset(
        lang, aead.aead_key_templates.AES128_GCM)
    encrypted_keyset = testing_servers.keyset_write_encrypted(
        lang, keyset, master_keyset, b'associated_data', keyset_writer_type)
    output_keyset = testing_servers.keyset_read_encrypted(
        lang, encrypted_keyset, master_keyset, b'associated_data',
        keyset_reader_type)
    self.assertEqual(output_keyset, keyset)

    with self.assertRaises(tink.TinkError):
      testing_servers.keyset_read_encrypted(lang, encrypted_keyset,
                                            master_keyset,
                                            b'invalid_associated_data',
                                            keyset_reader_type)
    with self.assertRaises(tink.TinkError):
      testing_servers.keyset_read_encrypted(lang, b'invalid_encrypted_keyset',
                                            master_keyset, b'associated_data',
                                            keyset_reader_type)
    with self.assertRaises(tink.TinkError):
      testing_servers.keyset_read_encrypted(lang, encrypted_keyset,
                                            b'invalid_master_keyset',
                                            b'associated_data',
                                            keyset_reader_type)
    with self.assertRaises(tink.TinkError):
      testing_servers.keyset_write_encrypted(lang, keyset,
                                             b'invalid_master_keyset',
                                             b'associated_data',
                                             keyset_writer_type)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['aead'])
  def test_aead(self, lang):
    keyset = testing_servers.new_keyset(lang,
                                        aead.aead_key_templates.AES128_GCM)
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    aead_primitive = testing_servers.remote_primitive(lang, keyset, aead.Aead)
    ciphertext = aead_primitive.encrypt(plaintext, associated_data)
    output = aead_primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

    with self.assertRaises(tink.TinkError):
      aead_primitive.decrypt(b'foo', associated_data)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['daead'])
  def test_daead(self, lang):
    keyset = testing_servers.new_keyset(
        lang, daead.deterministic_aead_key_templates.AES256_SIV)
    plaintext = b'The quick brown fox jumps over the lazy dog'
    associated_data = b'associated_data'
    daead_primitive = testing_servers.remote_primitive(lang, keyset,
                                                       daead.DeterministicAead)
    ciphertext = daead_primitive.encrypt_deterministically(
        plaintext, associated_data)
    output = daead_primitive.decrypt_deterministically(
        ciphertext, associated_data)
    self.assertEqual(output, plaintext)

    with self.assertRaises(tink.TinkError):
      daead_primitive.decrypt_deterministically(b'foo', associated_data)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['streaming_aead'])
  def test_streaming_aead(self, lang):
    keyset = testing_servers.new_keyset(
        lang, streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB)
    plaintext = b'The quick brown fox jumps over the lazy dog'
    plaintext_stream = io.BytesIO(plaintext)
    associated_data = b'associated_data'
    streaming_aead_primitive = testing_servers.remote_primitive(
        lang, keyset, streaming_aead.StreamingAead)
    ciphertext_stream = streaming_aead_primitive.new_encrypting_stream(
        plaintext_stream, associated_data)
    output_stream = streaming_aead_primitive.new_decrypting_stream(
        ciphertext_stream, associated_data)
    self.assertEqual(output_stream.read(), plaintext)

    with self.assertRaises(tink.TinkError):
      streaming_aead_primitive.new_decrypting_stream(io.BytesIO(b'foo'),
                                                     associated_data)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['mac'])
  def test_mac(self, lang):
    keyset = testing_servers.new_keyset(
        lang, mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    data = b'The quick brown fox jumps over the lazy dog'
    mac_primitive = testing_servers.remote_primitive(lang, keyset, mac.Mac)
    mac_value = mac_primitive.compute_mac(data)
    mac_primitive.verify_mac(mac_value, data)

    with self.assertRaises(tink.TinkError):
      mac_primitive.verify_mac(b'foo', data)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['hybrid'])
  def test_hybrid(self, lang):
    private_handle = testing_servers.new_keyset(
        lang,
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    public_handle = testing_servers.public_keyset(lang, private_handle)
    enc_primitive = testing_servers.remote_primitive(lang, public_handle,
                                                     hybrid.HybridEncrypt)
    data = b'The quick brown fox jumps over the lazy dog'
    context_info = b'context'
    ciphertext = enc_primitive.encrypt(data, context_info)
    dec_primitive = testing_servers.remote_primitive(lang, private_handle,
                                                     hybrid.HybridDecrypt)
    output = dec_primitive.decrypt(ciphertext, context_info)
    self.assertEqual(output, data)

    with self.assertRaises(tink.TinkError):
      dec_primitive.decrypt(b'foo', context_info)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['signature'])
  def test_signature(self, lang):
    private_handle = testing_servers.new_keyset(
        lang, signature.signature_key_templates.ED25519)
    public_handle = testing_servers.public_keyset(lang, private_handle)
    sign_primitive = testing_servers.remote_primitive(lang, private_handle,
                                                      signature.PublicKeySign)
    data = b'The quick brown fox jumps over the lazy dog'
    signature_value = sign_primitive.sign(data)
    verify_primitive = testing_servers.remote_primitive(
        lang, public_handle, signature.PublicKeyVerify)
    verify_primitive.verify(signature_value, data)

    with self.assertRaises(tink.TinkError):
      verify_primitive.verify(b'foo', data)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['prf'])
  def test_prf(self, lang):
    keyset = testing_servers.new_keyset(lang,
                                        prf.prf_key_templates.HMAC_SHA256)
    input_data = b'The quick brown fox jumps over the lazy dog'
    prf_set_primitive = testing_servers.remote_primitive(
        lang, keyset, prf.PrfSet)
    output = prf_set_primitive.primary().compute(input_data, output_length=15)
    self.assertLen(output, 15)

    with self.assertRaises(tink.TinkError):
      prf_set_primitive.primary().compute(input_data, output_length=123456)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['jwt'])
  def test_jwt_mac(self, lang):
    keyset = testing_servers.new_keyset(lang, jwt.jwt_hs256_template())

    jwt_mac_primitive = testing_servers.remote_primitive(
        lang, keyset, jwt.JwtMac)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    token = jwt.new_raw_jwt(
        issuer='issuer',
        subject='subject',
        audiences=['audience1', 'audience2'],
        jwt_id='jwt_id',
        expiration=now + datetime.timedelta(seconds=10),
        custom_claims={'switch': True, 'pi': 3.14159})
    compact = jwt_mac_primitive.compute_mac_and_encode(token)
    validator = jwt.new_validator(
        expected_issuer='issuer',
        expected_audience='audience1',
        fixed_now=now)
    verified_jwt = jwt_mac_primitive.verify_mac_and_decode(compact, validator)
    self.assertEqual(verified_jwt.issuer(), 'issuer')
    self.assertEqual(verified_jwt.subject(), 'subject')
    self.assertEqual(verified_jwt.jwt_id(), 'jwt_id')
    self.assertEqual(verified_jwt.custom_claim('switch'), True)
    self.assertEqual(verified_jwt.custom_claim('pi'), 3.14159)

    validator2 = jwt.new_validator(
        expected_audience='wrong_audience', fixed_now=now)
    with self.assertRaises(tink.TinkError):
      jwt_mac_primitive.verify_mac_and_decode(compact, validator2)

  @parameterized.parameters(_SUPPORTED_LANGUAGES['jwt'])
  def test_jwt_public_key_sign_verify(self, lang):
    private_keyset = testing_servers.new_keyset(lang, jwt.jwt_es256_template())
    public_keyset = testing_servers.public_keyset(lang, private_keyset)

    signer = testing_servers.remote_primitive(lang, private_keyset,
                                              jwt.JwtPublicKeySign)
    verifier = testing_servers.remote_primitive(lang, public_keyset,
                                                jwt.JwtPublicKeyVerify)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    token = jwt.new_raw_jwt(
        issuer='issuer',
        subject='subject',
        audiences=['audience1', 'audience2'],
        jwt_id='jwt_id',
        expiration=now + datetime.timedelta(seconds=10),
        custom_claims={'switch': True, 'pi': 3.14159})
    compact = signer.sign_and_encode(token)
    validator = jwt.new_validator(
        expected_issuer='issuer',
        expected_audience='audience1',
        fixed_now=now)
    verified_jwt = verifier.verify_and_decode(compact, validator)
    self.assertEqual(verified_jwt.issuer(), 'issuer')
    self.assertEqual(verified_jwt.subject(), 'subject')
    self.assertEqual(verified_jwt.jwt_id(), 'jwt_id')
    self.assertEqual(verified_jwt.custom_claim('switch'), True)
    self.assertEqual(verified_jwt.custom_claim('pi'), 3.14159)

    validator2 = jwt.new_validator(
        expected_audience='wrong_audience', fixed_now=now)
    with self.assertRaises(tink.TinkError):
      verifier.verify_and_decode(compact, validator2)

  @parameterized.parameters(['java'])
  def test_jwt_public_key_sign_export_import_verify(self, lang):
    private_keyset = testing_servers.new_keyset(lang, jwt.jwt_es256_template())
    public_keyset = testing_servers.public_keyset(lang, private_keyset)

    # sign and export public key
    signer = testing_servers.remote_primitive(lang, private_keyset,
                                              jwt.JwtPublicKeySign)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    token = jwt.new_raw_jwt(
        jwt_id='jwt_id', expiration=now + datetime.timedelta(seconds=100))
    compact = signer.sign_and_encode(token)
    public_jwk_set = testing_servers.jwk_set_from_keyset(lang, public_keyset)

    # verify using public_jwk_set
    imported_public_keyset = testing_servers.jwk_set_to_keyset(
        lang, public_jwk_set)

    verifier = testing_servers.remote_primitive(lang, imported_public_keyset,
                                                jwt.JwtPublicKeyVerify)
    validator = jwt.new_validator(fixed_now=now)
    verified_jwt = verifier.verify_and_decode(compact, validator)
    self.assertEqual(verified_jwt.jwt_id(), 'jwt_id')


if __name__ == '__main__':
  absltest.main()
