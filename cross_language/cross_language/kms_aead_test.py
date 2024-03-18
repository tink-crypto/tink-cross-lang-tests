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
import os
from typing import Dict, Iterable, List, Sequence, Tuple

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import aead

from tink.proto import tink_pb2
from cross_language.util import testing_servers
from cross_language.util import utilities

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

# This key was created with "derived=true".
_LOCAL_HCVAULT_DERIVED_KEY_URI = (
    'hcvault://127.0.0.1:8200/transit/keys/derived_testkey'
)

# This key was created with "derived=false".
_LOCAL_HCVAULT_KEY_URI = 'hcvault://127.0.0.1:8200/transit/keys/testkey'

_KMS_KEY_URI = {
    'GCP': _GCP_KEY_URI,
    'AWS': _AWS_KEY_URI,
    'HCVAULT': _LOCAL_HCVAULT_KEY_URI,
}

_KMS_KEY_URI_FOR_ENVELOPE_ENCRYPTION = {
    'GCP': _GCP_KEY_URI,
    'AWS': _AWS_KEY_URI,
    'HCVAULT': _LOCAL_HCVAULT_KEY_URI,
}

_DEK_TEMPLATE = utilities.KEY_TEMPLATE['AES128_GCM']


def _kms_envelope_aead_templates(
    kms_services: Sequence[str],
) -> Dict[Tuple[str, str], tink_pb2.KeyTemplate]:
  """Generates a map from KMS envelope AEAD template name to key template."""
  kms_key_templates = {}
  for kms_service in kms_services:
    key_uri = _KMS_KEY_URI_FOR_ENVELOPE_ENCRYPTION[kms_service]
    kms_envelope_aead_key_template = (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            key_uri, _DEK_TEMPLATE))
    kms_envelope_aead_template_name = '%s_KMS_ENVELOPE_AEAD' % kms_service
    kms_key_templates[(kms_service, kms_envelope_aead_template_name)] = (
        kms_envelope_aead_key_template
    )
  return kms_key_templates


# Maps from (kms_service, template_name) to template.
_KMS_ENVELOPE_AEAD_KEY_TEMPLATES = _kms_envelope_aead_templates(['GCP', 'AWS', 'HCVAULT'])
_SUPPORTED_LANGUAGES_FOR_KMS_ENVELOPE_AEAD = {
    'GCP': ('python', 'cc', 'go', 'java'),
    'AWS': ('python', 'cc', 'go', 'java'),
    'HCVAULT': ('python', 'go',),
}

_SUPPORTED_LANGUAGES_FOR_KMS_AEAD = {
    'AWS': ('python', 'cc', 'go', 'java'),
    'GCP': ('python', 'cc', 'go', 'java'),
    'HCVAULT': ('python', 'go'),
}


def setUpModule():
  aead.register()
  testing_servers.start('aead')


def tearDownModule():
  testing_servers.stop()


def _get_lang_tuples(langs: List[str]) -> Iterable[Tuple[str, str]]:
  """Yields language tuples to run cross-language tests.

  Ideally, we would want to the test all possible tuples of languages. But
  that results in a quadratic number of tuples. It is not really necessary,
  because if an implementation in one language does something different, then
  any cross-language test with another language will fail. So it is enough to
  only use every implementation once for encryption and once for decryption.

  Args:
    langs: List of language names.

  Yields:
    Tuples of 2 languages.
  """
  for i, _ in enumerate(langs):
    yield (langs[i], langs[((i + 1) % len(langs))])


def _kms_aead_test_cases() -> Iterable[Tuple[str, str, str, bytes, bytes]]:
  """Yields KMS AEAD test cases."""
  for plaintext, associated_data in [
      (b'plaintext', b''), (os.urandom(42), os.urandom(42)), (b'', b'')
  ]:
    for (
        kms_service,
        supported_langs,
    ) in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.items():
      for encrypt_lang, decrypt_lang in _get_lang_tuples(supported_langs):
        yield (
            kms_service,
            encrypt_lang,
            decrypt_lang,
            plaintext,
            associated_data,
        )


def _two_key_uris_test_cases():
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('AWS', []):
    yield (lang, _AWS_KEY_URI, _AWS_KEY_2_URI)
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('GCP', []):
    yield (lang, _GCP_KEY_URI, _GCP_KEY_2_URI)


def _key_uris_with_alias_test_cases():
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('AWS', []):
    yield (lang, _AWS_KEY_ALIAS_URI)


def _two_key_uris_with_alias_test_cases():
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('AWS', []):
    yield (lang, _AWS_KEY_ALIAS_URI, _AWS_KEY_2_ALIAS_URI)


def _unknown_key_uris_test_cases():
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('AWS', []):
    yield (lang, _AWS_UNKNOWN_KEY_URI)
    yield (lang, _AWS_UNKNOWN_KEY_ALIAS_URI)
  for lang in _SUPPORTED_LANGUAGES_FOR_KMS_AEAD.get('GCP', []):
    yield (lang, _GCP_UNKNOWN_KEY_URI)


class KmsAeadTest(parameterized.TestCase):

  def test_get_lang_tuples(self):
    self.assertEqual(
        list(_get_lang_tuples(['cc', 'java', 'go', 'python'])),
        [('cc', 'java'), ('java', 'go'), ('go', 'python'), ('python', 'cc')],
    )
    self.assertEqual(list(_get_lang_tuples([])), [])
    self.assertEqual(list(_get_lang_tuples(['go'])), [('go', 'go')])

  @parameterized.parameters(_kms_aead_test_cases())
  def test_encrypt_decrypt(
      self, kms_service, encrypt_lang, decrypt_lang, plaintext, associated_data
  ):
    kms_key_uri = _KMS_KEY_URI[kms_service]
    key_template = aead.aead_key_templates.create_kms_aead_key_template(
        kms_key_uri)
    keyset = testing_servers.new_keyset(encrypt_lang, key_template)
    encrypt_primitive = testing_servers.remote_primitive(
        lang=encrypt_lang, keyset=keyset, primitive_class=aead.Aead)
    if kms_service == 'AWS' and not plaintext:
      # AWS does not allow empty plaintext.
      with self.assertRaises(tink.TinkError):
        encrypt_primitive.encrypt(plaintext, associated_data)
      return
    if (
        kms_service == 'HCVAULT'
        and encrypt_lang == 'python'
        and associated_data
    ):
      # HCVAULT in python does not yet support associated_data
      # See https://github.com/hvac/hvac/issues/1107.
      with self.assertRaises(tink.TinkError):
        encrypt_primitive.encrypt(plaintext, associated_data)
      return
    ciphertext = encrypt_primitive.encrypt(plaintext, associated_data)
    decrypt_primitive = testing_servers.remote_primitive(
        decrypt_lang, keyset, aead.Aead)
    if (
        kms_service == 'HCVAULT'
        and decrypt_lang == 'python'
        and associated_data
    ):
      # HCVAULT in python does not yet support associated_data
      # See https://github.com/hvac/hvac/issues/1107.
      with self.assertRaises(tink.TinkError):
        decrypt_primitive.decrypt(ciphertext, associated_data)
      return
    output = decrypt_primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

    # test that when associated_data is modified, decryption fails.
    with self.assertRaises(tink.TinkError):
      decrypt_primitive.decrypt(ciphertext, associated_data + b'2')

  def test_hcvault_encrypt_decrypt_with_derived_key_fails(self):
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    kms_key_uri = _LOCAL_HCVAULT_DERIVED_KEY_URI
    key_template = aead.aead_key_templates.create_kms_aead_key_template(
        kms_key_uri
    )
    keyset = testing_servers.new_keyset('go', key_template)
    primitive = testing_servers.remote_primitive(
        lang='go', keyset=keyset, primitive_class=aead.Aead
    )
    # A derived key in HC vault requires the "context" parameter to be set.
    with self.assertRaises(tink.TinkError):
      _ = primitive.encrypt(plaintext, associated_data)

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

  @parameterized.parameters(_key_uris_with_alias_test_cases())
  def test_encrypt_decrypt_with_key_aliases(self, lang, alias_key_uri):
    keyset = testing_servers.new_keyset(
        lang,
        aead.aead_key_templates.create_kms_aead_key_template(alias_key_uri))
    primitive = testing_servers.remote_primitive(
        lang=lang, keyset=keyset, primitive_class=aead.Aead)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(
        primitive.decrypt(ciphertext, associated_data), plaintext)

  @parameterized.parameters(_two_key_uris_with_alias_test_cases())
  def test_cannot_decrypt_ciphertext_of_other_alias_key_uri(
      self, lang, alias_key_uri, alias_key_uri_2):
    keyset = testing_servers.new_keyset(
        lang,
        aead.aead_key_templates.create_kms_aead_key_template(alias_key_uri))
    keyset_2 = testing_servers.new_keyset(
        lang,
        aead.aead_key_templates.create_kms_aead_key_template(alias_key_uri_2))

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


def _kms_envelope_aead_test_cases() -> (
    Iterable[Tuple[str, str, str, bytes, bytes]]
):
  """Yields KMS Envelope AEAD test cases."""
  for plaintext, associated_data in [
      (b'plaintext', b''), (os.urandom(42), os.urandom(42)), (b'', b'')
  ]:
    for kms_service, key_template_name in _KMS_ENVELOPE_AEAD_KEY_TEMPLATES:
      # Make sure to test languages that support the pritive used for DEK.
      supported_langs = _SUPPORTED_LANGUAGES_FOR_KMS_ENVELOPE_AEAD[kms_service]
      for encrypt_lang, decrypt_lang in _get_lang_tuples(supported_langs):
        yield (
            kms_service,
            key_template_name,
            encrypt_lang,
            decrypt_lang,
            plaintext,
            associated_data,
        )


class KmsEnvelopeAeadTest(parameterized.TestCase):

  @parameterized.parameters(_kms_envelope_aead_test_cases())
  def test_encrypt_decrypt_with_associated_data(
      self,
      kms_service,
      key_template_name,
      encrypt_lang,
      decrypt_lang,
      plaintext,
      associated_data,
  ):
    key_template = _KMS_ENVELOPE_AEAD_KEY_TEMPLATES[
        (kms_service, key_template_name)
    ]
    # Use the encryption language to generate the keyset proto.
    keyset = testing_servers.new_keyset(encrypt_lang, key_template)
    encrypt_primitive = testing_servers.remote_primitive(
        encrypt_lang, keyset, aead.Aead)
    ciphertext = encrypt_primitive.encrypt(plaintext, associated_data)
    decrypt_primitive = testing_servers.remote_primitive(
        decrypt_lang, keyset, aead.Aead)
    output = decrypt_primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

    # test that when associated_data is modified, decryption fails.
    with self.assertRaises(tink.TinkError):
      decrypt_primitive.decrypt(ciphertext, associated_data + b'2')


if __name__ == '__main__':
  absltest.main()
