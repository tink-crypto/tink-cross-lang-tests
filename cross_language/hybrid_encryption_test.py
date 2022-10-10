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
"""Cross-language tests for Hybrid Encryption."""

from typing import Iterable, Tuple

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead
from tink import daead
from tink import hybrid

from tink.proto import common_pb2
from tink.proto import tink_pb2
from tink.testing import keyset_builder
from util import testing_servers
from util import utilities

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['hybrid']


def setUpModule():
  hybrid.register()
  testing_servers.start('hybrid')


def tearDownModule():
  testing_servers.stop()


# maps from key_template_name to (key_template, supported_langs)
_ADDITIONAL_KEY_TEMPLATES = {
    'ECIES_P256_HKDF_HMAC_SHA256_AES256_SIV':
        (hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
            curve_type=common_pb2.NIST_P256,
            ec_point_format=common_pb2.COMPRESSED,
            hash_type=common_pb2.SHA256,
            dem_key_template=daead.deterministic_aead_key_templates.AES256_SIV),
         ['cc', 'java', 'go', 'python']),
    'ECIES_P256_HKDF_HMAC_SHA256_XCHACHA20_POLY1305':
        (hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
            curve_type=common_pb2.NIST_P256,
            ec_point_format=common_pb2.UNCOMPRESSED,
            hash_type=common_pb2.SHA256,
            dem_key_template=aead.aead_key_templates.XCHACHA20_POLY1305),
         # Java and Go do not support XCHACHA20_POLY1305 for hybrid encryption.
         ['cc', 'python']),
    # equal to HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128Gcm
    'ECIES_X25519_HKDF_HMAC_SHA256_AES128_GCM':
        (hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
            curve_type=common_pb2.CURVE25519,
            ec_point_format=common_pb2.COMPRESSED,
            hash_type=common_pb2.SHA256,
            dem_key_template=aead.aead_key_templates.AES128_GCM),
         # Java and Go do not support CURVE25519 for hybrid encryption.
         ['cc', 'python']),
    # equal to HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128CtrHmacSha256
    'ECIES_X25519_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256':
        (hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
            curve_type=common_pb2.CURVE25519,
            ec_point_format=common_pb2.COMPRESSED,
            hash_type=common_pb2.SHA256,
            dem_key_template=aead.aead_key_templates.AES128_CTR_HMAC_SHA256),
         # Java and Go do not support CURVE25519 for hybrid encryption.
         ['cc', 'python']),
    # equal to HybridKeyTemplates::EciesX25519HkdfHmacSha256XChaCha20Poly1305
    'ECIES_X25519_HKDF_HMAC_SHA256_XCHACHA20_POLY1305':
        (hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
            curve_type=common_pb2.CURVE25519,
            ec_point_format=common_pb2.COMPRESSED,
            hash_type=common_pb2.SHA256,
            dem_key_template=aead.aead_key_templates.XCHACHA20_POLY1305),
         # Java and Go neither support CURVE25519 nor XCHACHA20_POLY130 for
         # Hybrid Encryption.
         ['cc', 'python']),
    # equal to HybridKeyTemplates::EciesX25519HkdfHmacSha256DeterministicAesSiv
    'ECIES_X25519_HKDF_HMAC_SHA256_AES256_SIV':
        (hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
            curve_type=common_pb2.CURVE25519,
            ec_point_format=common_pb2.COMPRESSED,
            hash_type=common_pb2.SHA256,
            dem_key_template=daead.deterministic_aead_key_templates.AES256_SIV),
         # Java and Go do not support CURVE25519 for Hybrid Encryption.
         ['cc', 'python']),
}


class HybridEncryptionTest(parameterized.TestCase):

  @parameterized.parameters([
      *utilities.tinkey_template_names_for(hybrid.HybridDecrypt),
      *_ADDITIONAL_KEY_TEMPLATES.keys()
  ])
  def test_encrypt_decrypt(self, key_template_name):
    if key_template_name in _ADDITIONAL_KEY_TEMPLATES:
      key_template, supported_langs = _ADDITIONAL_KEY_TEMPLATES[
          key_template_name]
    else:
      key_template = utilities.KEY_TEMPLATE[key_template_name]
      supported_langs = (
          utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[key_template_name])
    self.assertNotEmpty(supported_langs)
    # Take the first supported language to generate the private keyset.
    private_keyset = testing_servers.new_keyset(supported_langs[0],
                                                key_template)
    supported_decs = [
        testing_servers.remote_primitive(lang, private_keyset,
                                         hybrid.HybridDecrypt)
        for lang in supported_langs
    ]
    public_keyset = testing_servers.public_keyset(supported_langs[0],
                                                  private_keyset)
    supported_encs = {
        lang: testing_servers.remote_primitive(lang, public_keyset,
                                               hybrid.HybridEncrypt)
        for lang in supported_langs
    }
    for lang, hybrid_encrypt in supported_encs.items():
      plaintext = (
          b'This is some plaintext message to be encrypted using key_template '
          b'%s in %s.' %
          (key_template_name.encode('utf8'), lang.encode('utf8')))
      context_info = (b'Some context info for %s using %s for encryption.' %
                      (key_template_name.encode('utf8'), lang.encode('utf8')))
      ciphertext = hybrid_encrypt.encrypt(plaintext, context_info)
      for dec in supported_decs:
        output = dec.decrypt(ciphertext, context_info)
        self.assertEqual(output, plaintext)


# If the implementations work fine for keysets with single keys, then key
# rotation should work if the primitive wrapper is implemented correctly.
# These wrappers do not depend on the key type, so it should be fine to always
# test with the same key type. But since the wrapper needs to treat keys
# with output prefix RAW differently, we also include such a template for that.
KEY_ROTATION_TEMPLATES = [
    hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
    keyset_builder.raw_template(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
]


def key_rotation_test_cases(
) -> Iterable[Tuple[str, str, tink_pb2.KeyTemplate, tink_pb2.KeyTemplate]]:
  for enc_lang in SUPPORTED_LANGUAGES:
    for dec_lang in SUPPORTED_LANGUAGES:
      for old_key_tmpl in KEY_ROTATION_TEMPLATES:
        for new_key_tmpl in KEY_ROTATION_TEMPLATES:
          yield (enc_lang, dec_lang, old_key_tmpl, new_key_tmpl)


class HybridEncryptionKeyRotationTest(parameterized.TestCase):

  @parameterized.parameters(key_rotation_test_cases())
  def test_key_rotation(self, enc_lang, dec_lang, old_key_tmpl, new_key_tmpl):
    # Do a key rotation from an old key generated from old_key_tmpl to a new
    # key generated from new_key_tmpl. Encryption and decryption are done
    # in languages enc_lang and dec_lang.
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)
    builder.set_primary_key(older_key_id)
    dec1 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                            hybrid.HybridDecrypt)
    enc1 = testing_servers.remote_primitive(dec_lang, builder.public_keyset(),
                                            hybrid.HybridEncrypt)
    newer_key_id = builder.add_new_key(new_key_tmpl)
    dec2 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                            hybrid.HybridDecrypt)
    enc2 = testing_servers.remote_primitive(dec_lang, builder.public_keyset(),
                                            hybrid.HybridEncrypt)

    builder.set_primary_key(newer_key_id)
    dec3 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                            hybrid.HybridDecrypt)
    enc3 = testing_servers.remote_primitive(dec_lang, builder.public_keyset(),
                                            hybrid.HybridEncrypt)

    builder.disable_key(older_key_id)
    dec4 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                            hybrid.HybridDecrypt)
    enc4 = testing_servers.remote_primitive(dec_lang, builder.public_keyset(),
                                            hybrid.HybridEncrypt)
    self.assertNotEqual(older_key_id, newer_key_id)

    # p1 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext1 = enc1.encrypt(b'plaintext', b'context')
    self.assertEqual(dec1.decrypt(ciphertext1, b'context'), b'plaintext')
    self.assertEqual(dec2.decrypt(ciphertext1, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext1, b'context'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec4.decrypt(ciphertext1, b'context')

    # p2 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext2 = enc2.encrypt(b'plaintext', b'context')
    self.assertEqual(dec1.decrypt(ciphertext2, b'context'), b'plaintext')
    self.assertEqual(dec2.decrypt(ciphertext2, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext2, b'context'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec4.decrypt(ciphertext2, b'context')

    # p3 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext3 = enc3.encrypt(b'plaintext', b'context')
    with self.assertRaises(tink.TinkError):
      _ = dec1.decrypt(ciphertext3, b'context')
    self.assertEqual(dec2.decrypt(ciphertext3, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext3, b'context'), b'plaintext')
    self.assertEqual(dec4.decrypt(ciphertext3, b'context'), b'plaintext')

    # p4 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext4 = enc4.encrypt(b'plaintext', b'context')
    with self.assertRaises(tink.TinkError):
      _ = dec1.decrypt(ciphertext4, b'context')
    self.assertEqual(dec2.decrypt(ciphertext4, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext4, b'context'), b'plaintext')
    self.assertEqual(dec4.decrypt(ciphertext4, b'context'), b'plaintext')


if __name__ == '__main__':
  absltest.main()
