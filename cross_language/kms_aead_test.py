# Copyright 2022 Google LLC
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
"""Cross-language tests for the KMS Envelope AEAD primitive with AWS and GCP."""
import itertools

from typing import Dict, Iterable, Tuple, Sequence

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead

from tink.proto import tink_pb2
import tink_config
from util import testing_servers
from util import utilities

# AWS Key with alias "unit-and-integration-testing"
_AWS_KEY_URI = ('aws-kms://arn:aws:kms:us-east-2:235739564943:key/'
                '3ee50705-5a82-4f5b-9753-05c4f473922f')
_AWS_KEY_ALIAS_URI = ('aws-kms://arn:aws:kms:us-east-2:235739564943:alias/'
                      'unit-and-integration-testing')


# 2nd AWS Key with alias "unit-and-integration-testing-2"
_AWS_KEY_2_URI = ('aws-kms://arn:aws:kms:us-east-2:235739564943:key/'
                  'b3ca2efd-a8fb-47f2-b541-7e20f8c5cd11')
_AWS_KEY_2_ALIAS_URI = ('aws-kms://arn:aws:kms:us-east-2:235739564943:alias/'
                        'unit-and-integration-testing-2')

_AWS_UNKNOWN_KEY_URI = ('aws-kms://arn:aws:kms:us-east-2:235739564943:key/'
                        '4ee50705-5a82-4f5b-9753-05c4f473922f')
_AWS_UNKNOWN_KEY_ALIAS_URI = (
    'aws-kms://arn:aws:kms:us-east-2:235739564943:alias/'
    'unknown-unit-and-integration-testing')

_GCP_KEY_URI = ('gcp-kms://projects/tink-test-infrastructure/locations/global/'
                'keyRings/unit-and-integration-testing/cryptoKeys/aead-key')
_GCP_KEY_2_URI = (
    'gcp-kms://projects/tink-test-infrastructure/locations/global/'
    'keyRings/unit-and-integration-testing/cryptoKeys/aead2-key')
_GCP_UNKNOWN_KEY_URI = (
    'gcp-kms://projects/tink-test-infrastructure/locations/global/'
    'keyRings/unit-and-integration-testing/cryptoKeys/unknown')


_KMS_KEY_URI = {
    'GCP': _GCP_KEY_URI,
    'AWS': _AWS_KEY_URI,
}


def _kms_envelope_aead_templates(
    kms_services: Sequence[str]) -> Dict[str, Tuple[tink_pb2.KeyTemplate, str]]:
  """For each KMS envelope AEAD template name maps the key template and DEK AEAD key type."""
  kms_key_templates = {}
  for kms_service in kms_services:
    key_uri = _KMS_KEY_URI[kms_service]
    for aead_key_type in tink_config.key_types_for_primitive(aead.Aead):
      for key_template_name in utilities.KEY_TEMPLATE_NAMES[aead_key_type]:
        kms_envelope_aead_key_template = (
            aead.aead_key_templates.create_kms_envelope_aead_key_template(
                key_uri, utilities.KEY_TEMPLATE[key_template_name]))
        kms_envelope_aead_template_name = '%s_KMS_ENVELOPE_AEAD_WITH_%s' % (
            kms_service, key_template_name)
        kms_key_templates[kms_envelope_aead_template_name] = (
            kms_envelope_aead_key_template, aead_key_type)
  return kms_key_templates


_KMS_ENVELOPE_AEAD_KEY_TEMPLATES = _kms_envelope_aead_templates(['GCP', 'AWS'])
_SUPPORTED_LANGUAGES_FOR_KMS_ENVELOPE_AEAD = ('python', 'cc', 'go', 'java')

# Currently Go doesn't support KmsAeadKey.
_SUPPORTED_LANGUAGES_FOR_KMS_AEAD = {
    'AWS': ('python', 'cc', 'java'),
    'GCP': ('python', 'cc', 'java'),
}


def setUpModule():
  aead.register()
  testing_servers.start('aead')


def tearDownModule():
  testing_servers.stop()


def _get_plaintext_and_aad(key_template_name: str,
                           lang: str) -> Tuple[bytes, bytes]:
  """Creates test plaintext and associated data from a key template and lang."""
  plaintext = (
      b'This is some plaintext message to be encrypted using key_template '
      b'%s using %s for encryption.' %
      (key_template_name.encode('utf8'), lang.encode('utf8')))
  associated_data = (b'Some associated data for %s using %s for encryption.' %
                     (key_template_name.encode('utf8'), lang.encode('utf8')))
  return (plaintext, associated_data)


def _kms_aead_test_cases() -> Iterable[Tuple[str, str, str]]:
  """Yields (KMS service, encrypt lang, decrypt lang)."""
  for kms_service, supported_langs in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.items():
    for encrypt_lang, decrypt_lang in itertools.product(supported_langs,
                                                        supported_langs):
      yield (kms_service, encrypt_lang, decrypt_lang)


def _two_key_uris_test_cases():
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('AWS', []):
    yield (lang, _AWS_KEY_URI, _AWS_KEY_2_URI)
    yield (lang, _AWS_KEY_ALIAS_URI, _AWS_KEY_2_ALIAS_URI)
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('GCP', []):
    yield (lang, _GCP_KEY_URI, _GCP_KEY_2_URI)


def _unknown_key_uris_test_cases():
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('AWS', []):
    yield (lang, _AWS_UNKNOWN_KEY_URI)
    yield (lang, _AWS_UNKNOWN_KEY_ALIAS_URI)
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('GCP', []):
    yield (lang, _GCP_UNKNOWN_KEY_URI)


class KmsAeadTest(parameterized.TestCase):

  @parameterized.parameters(_kms_aead_test_cases())
  def test_encrypt_decrypt(self, kms_service, encrypt_lang, decrypt_lang):
    kms_key_uri = _KMS_KEY_URI[kms_service]
    kms_aead_template_name = '%s_KMS_AEAD' % kms_service
    key_template = aead.aead_key_templates.create_kms_aead_key_template(
        kms_key_uri)
    keyset = testing_servers.new_keyset(encrypt_lang, key_template)
    encrypt_primitive = testing_servers.remote_primitive(
        lang=encrypt_lang, keyset=keyset, primitive_class=aead.Aead)
    plaintext, associated_data = _get_plaintext_and_aad(kms_aead_template_name,
                                                        encrypt_primitive.lang)
    ciphertext = encrypt_primitive.encrypt(plaintext, associated_data)
    decrypt_primitive = testing_servers.remote_primitive(
        decrypt_lang, keyset, aead.Aead)
    output = decrypt_primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

  @parameterized.parameters(_two_key_uris_test_cases())
  def test_cannot_decrypt_ciphertext_of_other_key_uri(self, lang, key_uri,
                                                      key_uri_2):
    keyset = testing_servers.new_keyset(
        lang, aead.aead_key_templates.create_kms_aead_key_template(key_uri))
    keyset_2 = testing_servers.new_keyset(
        lang, aead.aead_key_templates.create_kms_aead_key_template(key_uri_2))

    primitive = testing_servers.remote_primitive(
        lang=lang, keyset=keyset, primitive_class=aead.Aead)
    primitive_2 = testing_servers.remote_primitive(
        lang=lang, keyset=keyset_2, primitive_class=aead.Aead)

    plaintext = b'plaintext'
    associated_data = b'associated_data'

    ciphertext = primitive.encrypt(plaintext, associated_data)
    ciphertext_2 = primitive_2.encrypt(plaintext, associated_data)

    # Can be decrypted by the primtive that created the ciphertext.
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)
    self.assertEqual(
        primitive_2.decrypt(ciphertext_2, associated_data), plaintext)

    # Cannot be decrypted by the other primitive.
    with self.assertRaises(tink.TinkError):
      primitive.decrypt(ciphertext_2, associated_data)
    with self.assertRaises(tink.TinkError):
      primitive_2.decrypt(ciphertext, associated_data)

  @parameterized.parameters(_unknown_key_uris_test_cases())
  def test_encrypt_fails_with_unknown_key_uri(self, lang, unknown_key_uri):
    key_template = aead.aead_key_templates.create_kms_aead_key_template(
        unknown_key_uri)
    keyset = testing_servers.new_keyset(lang, key_template)
    primitive = testing_servers.remote_primitive(
        lang=lang, keyset=keyset, primitive_class=aead.Aead)

    plaintext = b'plaintext'
    associated_data = b'associated_data'

    with self.assertRaises(tink.TinkError):
      primitive.encrypt(plaintext, associated_data)


def _kms_envelope_aead_test_cases() -> Iterable[Tuple[str, str, str]]:
  """Yields (KMS Envelope AEAD template names, encrypt lang, decrypt lang)."""
  for key_template_name, (
      _, aead_key_type) in _KMS_ENVELOPE_AEAD_KEY_TEMPLATES.items():
    # Make sure to test languages that support the pritive used for DEK.
    supported_langs = tink_config.supported_languages_for_key_type(
        aead_key_type)
    # Make sure the language supports KMS envelope encryption.
    supported_langs = set(supported_langs).intersection(
        _SUPPORTED_LANGUAGES_FOR_KMS_ENVELOPE_AEAD)
    for encrypt_lang in supported_langs:
      for decrypt_lang in supported_langs:
        yield (key_template_name, encrypt_lang, decrypt_lang)


class KmsEnvelopeAeadTest(parameterized.TestCase):

  @parameterized.parameters(_kms_envelope_aead_test_cases())
  def test_encrypt_decrypt(self, key_template_name, encrypt_lang, decrypt_lang):
    key_template, _ = _KMS_ENVELOPE_AEAD_KEY_TEMPLATES[key_template_name]
    # Use the encryption language to generate the keyset proto.
    keyset = testing_servers.new_keyset(encrypt_lang, key_template)
    encrypt_primitive = testing_servers.remote_primitive(
        encrypt_lang, keyset, aead.Aead)
    plaintext, associated_data = _get_plaintext_and_aad(key_template_name,
                                                        encrypt_primitive.lang)
    ciphertext = encrypt_primitive.encrypt(plaintext, associated_data)

    # Decrypt.
    decrypt_primitive = testing_servers.remote_primitive(
        decrypt_lang, keyset, aead.Aead)
    output = decrypt_primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

  @parameterized.parameters(_kms_envelope_aead_test_cases())
  def test_decryption_fails_with_wrong_aad(self, key_template_name,
                                           encrypt_lang, decrypt_lang):
    key_template, _ = _KMS_ENVELOPE_AEAD_KEY_TEMPLATES[key_template_name]
    # Use the encryption language to generate the keyset proto.
    keyset = testing_servers.new_keyset(encrypt_lang, key_template)
    encrypt_primitive = testing_servers.remote_primitive(
        encrypt_lang, keyset, aead.Aead)
    plaintext, associated_data = _get_plaintext_and_aad(key_template_name,
                                                        encrypt_primitive.lang)
    ciphertext = encrypt_primitive.encrypt(plaintext, associated_data)
    decrypt_primitive = testing_servers.remote_primitive(
        decrypt_lang, keyset, aead.Aead)
    with self.assertRaises(tink.TinkError, msg='decryption failed'):
      decrypt_primitive.decrypt(ciphertext, b'wrong aad')

if __name__ == '__main__':
  absltest.main()
