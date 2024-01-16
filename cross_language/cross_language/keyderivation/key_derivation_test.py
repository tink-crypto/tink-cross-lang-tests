# Copyright 2021 Google LLC
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
"""Cross-language tests for Key Derivation."""

from typing import Iterable, Optional, Tuple

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import aead
from tink import prf
from tink import secret_key_access

from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import prf_based_deriver_pb2
from tink.proto import tink_pb2
from cross_language.util import key_util
from cross_language.util import test_keys
from cross_language.util import testing_servers
from cross_language.util import utilities

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE[
    'keyset_deriver'
]

# For all key types, either no languages support its derivation or all languages
# support its derivation. This map lists exceptions, i.e. key types with a list
# of languages that cannot derive that key type.
NOT_YET_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME = {
    # AesGcmSivKey
    'AES128_GCM_SIV': ['cc', 'go'],
    'AES128_GCM_SIV_RAW': ['cc', 'go'],
    'AES256_GCM_SIV': ['cc', 'go'],
    'AES256_GCM_SIV_RAW': ['cc', 'go'],
    # AesCtrHmacKey:
    'AES128_CTR_HMAC_SHA256': ['go'],
    'AES128_CTR_HMAC_SHA256_RAW': ['go'],
    'AES256_CTR_HMAC_SHA256': ['go'],
    'AES256_CTR_HMAC_SHA256_RAW': ['go'],
    # AesCtrHmacStreamingKey
    'AES128_CTR_HMAC_SHA256_4KB': ['java', 'go'],
    'AES128_CTR_HMAC_SHA256_1MB': ['java', 'go'],
    'AES256_CTR_HMAC_SHA256_4KB': ['java', 'go'],
    'AES256_CTR_HMAC_SHA256_1MB': ['java', 'go'],
    # EcdsaPrivateKey
    'ECDSA_P256': ['java', 'go'],
    'ECDSA_P256_IEEE_P1363': ['java', 'go'],
    'ECDSA_P256_RAW': ['java', 'go'],
    'ECDSA_P384': ['java', 'go'],
    'ECDSA_P384_IEEE_P1363': ['java', 'go'],
    'ECDSA_P384_SHA384': ['java', 'go'],
    'ECDSA_P384_SHA384_IEEE_P1363': ['java', 'go'],
    'ECDSA_P384_SHA512': ['java', 'go'],
    'ECDSA_P521': ['java', 'go'],
    'ECDSA_P521_IEEE_P1363': ['java', 'go'],
    # AesCmacPrfKey
    'AES_CMAC_PRF': ['java', 'go'],
    # HkdfPrfKey
    'HKDF_SHA256': ['java'],
}


def setUpModule():
  testing_servers.start('key_derivation')
  aead.register()


def tearDownModule():
  testing_servers.stop()


def merge_keysets(keyset1: bytes, keyset2: bytes) -> bytes:
  """Merges all keys from the keysets into one keyset."""
  # TODO(juerg): Use the proper API for this, once it is ready.
  k1 = tink_pb2.Keyset.FromString(keyset1)
  k2 = tink_pb2.Keyset.FromString(keyset2)
  k1.key.extend(k2.key)
  return k1.SerializeToString()


def extract_sorted_keyset(keyset_handle: tink.KeysetHandle) -> tink_pb2.Keyset:
  """Extracts the keyset from a KeysetHandle."""
  keyset = tink.proto_keyset_format.serialize(
      keyset_handle, secret_key_access.TOKEN
  )
  output = tink_pb2.Keyset.FromString(keyset)
  # We need to sort the keys, because the C++ implementation of KeysetDeriver
  # does not preserve the ordering of the keys, see b/203512128.
  sorted_keys = sorted(output.key, key=lambda k: k.key_id)
  output.ClearField('key')
  output.key.extend(sorted_keys)
  return output


def prf_based_deriver_template(
    prf_key_template: tink_pb2.KeyTemplate,
    derived_key_template: tink_pb2.KeyTemplate,
) -> tink_pb2.KeyTemplate:
  key_format = prf_based_deriver_pb2.PrfBasedDeriverKeyFormat(
      prf_key_template=prf_key_template,
      params=prf_based_deriver_pb2.PrfBasedDeriverParams(
          derived_key_template=derived_key_template
      ),
  )
  return tink_pb2.KeyTemplate(
      type_url='type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey',
      output_prefix_type=derived_key_template.output_prefix_type,
      value=key_format.SerializeToString(),
  )


def all_derived_template_names() -> Iterable[str]:
  for derived_template_name in utilities.KEY_TEMPLATE.keys():
    yield derived_template_name


def all_template_names_with_supported_lang() -> Iterable[Tuple[str, str]]:
  for derived_template_name in utilities.KEY_TEMPLATE.keys():
    for lang in SUPPORTED_LANGUAGES:
      yield (derived_template_name, lang)


def inc_nested_template_version(
    template: tink_pb2.KeyTemplate,
) -> Optional[tink_pb2.KeyTemplate]:
  """For certain templates the version is nested."""
  if (template.type_url !=
      'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey'):
    return None
  proto = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKeyFormat()
  proto.ParseFromString(template.value)
  proto.hmac_key_format.version = proto.hmac_key_format.version + 1
  return tink_pb2.KeyTemplate(
      type_url=template.type_url,
      value=proto.SerializeToString(),
      output_prefix_type=template.output_prefix_type,
  )


def inc_template_version(
    template: tink_pb2.KeyTemplate,
) -> Optional[tink_pb2.KeyTemplate]:
  """If template has a version field, returns a template increased version."""
  proto_type = key_util.KeyProto.format_from_url(template.type_url)

  key_template_proto = proto_type.FromString(template.value)
  if not hasattr(key_template_proto, 'version'):
    return inc_nested_template_version(template)
  key_template_proto.version = key_template_proto.version + 1

  return tink_pb2.KeyTemplate(
      type_url=template.type_url,
      value=key_template_proto.SerializeToString(),
      output_prefix_type=template.output_prefix_type,
  )


class TestingServersTest(parameterized.TestCase):

  @parameterized.parameters(all_derived_template_names())
  def test_derive_keyset(self, derived_template_name):
    template = prf_based_deriver_template(
        prf.prf_key_templates.HKDF_SHA256,
        utilities.KEY_TEMPLATE[derived_template_name],
    )

    langs_supported_by_derived_template = set(
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[derived_template_name]
    )
    not_yet_supported_langs_by_derived_template = set(
        NOT_YET_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME.get(
            derived_template_name, set()
        )
    )
    # There are two options for languages in supported_languages: either they
    # all can derive derived_template_name or they all cannot.
    supported_languages = (
        set(SUPPORTED_LANGUAGES) & langs_supported_by_derived_template
    ) - not_yet_supported_langs_by_derived_template
    if not supported_languages:
      self.fail('no supported language for %s' % derived_template_name)

    # Derive a keyset in all supported languages.
    deriver_keyset = b''
    derived_keyset = {}
    for lang in supported_languages:
      try:
        # Construct a keyset with two keys using the first language in
        # supported_languages that succeeds.
        if not deriver_keyset:
          k1 = testing_servers.new_keyset(lang, template)
          k2 = testing_servers.new_keyset(lang, template)
          deriver_keyset = merge_keysets(k1, k2)
        deriver = testing_servers.keyset_deriver(lang, deriver_keyset)
        derived_keyset[lang] = extract_sorted_keyset(
            deriver.derive_keyset(b'salt')
        )
      # Ultimately, we want to count how many languages in supported_languages
      # are able to derive derived_template_name. Acceptable counts are either
      # 0 or len(supported_languages). TinkErrors are acceptable in the former
      # scenario, and both scenarios are checked below.
      except tink.TinkError:
        pass

    # No languages support derivation for template, which is acceptable.
    if not derived_keyset:
      return
    # If one language supports derivation for template, then all of
    # supported_languages must support derivation.
    self.assertCountEqual(derived_keyset.keys(), supported_languages)
    for lang1 in supported_languages:
      for lang2 in supported_languages:
        key_util.assert_tink_proto_equal(
            self,
            derived_keyset[lang1],
            derived_keyset[lang2],
            msg='derived keyset in %s and %s are not equal:' % (lang1, lang2),
        )

  @parameterized.parameters(all_template_names_with_supported_lang())
  def test_derive_keyset_validates_template_version(
      self, derived_template_name, lang
  ):
    derived_template = utilities.KEY_TEMPLATE[derived_template_name]
    derived_template_with_inc_version = inc_template_version(derived_template)
    if not derived_template_with_inc_version:
      # template does not have a version. verify that keyset derivation is
      # not supported.
      template = prf_based_deriver_template(
          prf.prf_key_templates.HKDF_SHA256, derived_template
      )
      with self.assertRaises(tink.TinkError):
        deriver_keyset = testing_servers.new_keyset(lang, template)
        deriver = testing_servers.keyset_deriver(lang, deriver_keyset)
        _ = deriver.derive_keyset(b'salt')
    else:
      # template does have a version. Create an invalid version and check that
      # derivation fails. It either fails because it is not supported, or
      # because the invalid version is rejected. Both are fine.
      template = prf_based_deriver_template(
          prf.prf_key_templates.HKDF_SHA256, derived_template_with_inc_version
      )
      with self.assertRaises(tink.TinkError):
        deriver_keyset = testing_servers.new_keyset(lang, template)
        deriver = testing_servers.keyset_deriver(lang, deriver_keyset)
        _ = deriver.derive_keyset(b'salt')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_derive_aead_keyset(self, lang):
    template = prf_based_deriver_template(
        prf.prf_key_templates.HKDF_SHA256, aead.aead_key_templates.AES256_GCM
    )
    keyset = testing_servers.new_keyset(lang, template)
    deriver = testing_servers.keyset_deriver(lang, keyset)
    handle = deriver.derive_keyset(b'salt')
    primitive = handle.primitive(aead.Aead)
    ciphertext = primitive.encrypt(b'plaintext', b'ad')
    self.assertEqual(primitive.decrypt(ciphertext, b'ad'), b'plaintext')

    # decrypting with an Aead from a different salt fails
    handle2 = deriver.derive_keyset(b'salt2')
    primitive2 = handle2.primitive(aead.Aead)
    with self.assertRaises(tink.TinkError):
      primitive2.decrypt(ciphertext, b'ad')

  def test_primitive_creation_with_non_key_derivation_keyset_fails(self):
    keyset = test_keys.new_or_stored_keyset(
        utilities.KEY_TEMPLATE['AES128_EAX']
    )
    for lang in SUPPORTED_LANGUAGES:
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.keyset_deriver(lang, keyset)


if __name__ == '__main__':
  absltest.main()
