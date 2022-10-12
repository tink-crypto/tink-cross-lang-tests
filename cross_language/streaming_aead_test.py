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
"""Cross-language tests for the StreamingAead primitive."""

import io

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import streaming_aead

from tink.testing import keyset_builder
from util import testing_servers
from util import utilities

SUPPORTED_LANGUAGES = (testing_servers
                       .SUPPORTED_LANGUAGES_BY_PRIMITIVE['streaming_aead'])

# About 49KB.
LONG_PLAINTEXT = b' '.join(b'%d' % i for i in range(10000))


def key_rotation_test_cases():
  for enc_lang in SUPPORTED_LANGUAGES:
    for dec_lang in SUPPORTED_LANGUAGES:
      yield (enc_lang, dec_lang)


def setUpModule():
  streaming_aead.register()
  testing_servers.start('streaming_aead')


def tearDownModule():
  testing_servers.stop()


class StreamingAeadPythonTest(parameterized.TestCase):

  @parameterized.parameters(
      utilities.tinkey_template_names_for(streaming_aead.StreamingAead))
  def test_encrypt_decrypt(self, key_template_name):
    supported_langs = utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = utilities.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)
    supported_streaming_aeads = {}
    for lang in supported_langs:
      supported_streaming_aeads[lang] = testing_servers.remote_primitive(
          lang, keyset, streaming_aead.StreamingAead)
    for lang, p in supported_streaming_aeads.items():
      desc = (
          b'This is some plaintext message to be encrypted using key_template '
          b'%s using %s for encryption.'
          % (key_template_name.encode('utf8'), lang.encode('utf8')))
      plaintext = desc + LONG_PLAINTEXT
      associated_data = (
          b'Some associated data for %s using %s for encryption.' %
          (key_template_name.encode('utf8'), lang.encode('utf8')))
      plaintext_stream = io.BytesIO(plaintext)
      ciphertext_result_stream = p.new_encrypting_stream(
          plaintext_stream, associated_data)
      ciphertext = ciphertext_result_stream.read()
      for _, p2 in supported_streaming_aeads.items():
        ciphertext_stream = io.BytesIO(ciphertext)
        decrypted_stream = p2.new_decrypting_stream(
            ciphertext_stream, associated_data)
        self.assertEqual(decrypted_stream.read(), plaintext)

  @parameterized.parameters(key_rotation_test_cases())
  def test_key_rotation(self, enc_lang, dec_lang):
    # Do a key rotation from an old key to a new key.
    # Encryption and decryption are done in languages enc_lang and dec_lang.
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB)
    builder.set_primary_key(older_key_id)
    enc1 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                            streaming_aead.StreamingAead)
    dec1 = testing_servers.remote_primitive(dec_lang, builder.keyset(),
                                            streaming_aead.StreamingAead)
    newer_key_id = builder.add_new_key(
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_4KB)
    enc2 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                            streaming_aead.StreamingAead)
    dec2 = testing_servers.remote_primitive(dec_lang, builder.keyset(),
                                            streaming_aead.StreamingAead)

    builder.set_primary_key(newer_key_id)
    enc3 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                            streaming_aead.StreamingAead)
    dec3 = testing_servers.remote_primitive(dec_lang, builder.keyset(),
                                            streaming_aead.StreamingAead)

    builder.disable_key(older_key_id)
    enc4 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                            streaming_aead.StreamingAead)
    dec4 = testing_servers.remote_primitive(dec_lang, builder.keyset(),
                                            streaming_aead.StreamingAead)

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 encrypts with the older key. So 1, 2 and 3 can decrypt it, but not 4.
    plaintext = LONG_PLAINTEXT
    ad = b'associated_data'
    ciphertext1 = enc1.new_encrypting_stream(io.BytesIO(plaintext), ad).read()
    self.assertEqual(
        dec1.new_decrypting_stream(io.BytesIO(ciphertext1), ad).read(),
        plaintext)
    self.assertEqual(
        dec2.new_decrypting_stream(io.BytesIO(ciphertext1), ad).read(),
        plaintext)
    self.assertEqual(
        dec3.new_decrypting_stream(io.BytesIO(ciphertext1), ad).read(),
        plaintext)
    with self.assertRaises(tink.TinkError):
      _ = dec4.new_decrypting_stream(io.BytesIO(ciphertext1), ad).read()

    # 2 encrypts with the older key. So 1, 2 and 3 can decrypt it, but not 4.
    ciphertext2 = enc2.new_encrypting_stream(io.BytesIO(plaintext), ad).read()
    self.assertEqual(
        dec1.new_decrypting_stream(io.BytesIO(ciphertext2), ad).read(),
        plaintext)
    self.assertEqual(
        dec2.new_decrypting_stream(io.BytesIO(ciphertext2), ad).read(),
        plaintext)
    self.assertEqual(
        dec3.new_decrypting_stream(io.BytesIO(ciphertext2), ad).read(),
        plaintext)
    with self.assertRaises(tink.TinkError):
      _ = dec4.new_decrypting_stream(io.BytesIO(ciphertext2), ad).read()

    # 3 encrypts with the newer key. So 2, 3 and 4 can decrypt it, but not 1.
    ciphertext3 = enc3.new_encrypting_stream(io.BytesIO(plaintext), ad).read()
    with self.assertRaises(tink.TinkError):
      _ = dec1.new_decrypting_stream(io.BytesIO(ciphertext3), ad).read()
    self.assertEqual(
        dec2.new_decrypting_stream(io.BytesIO(ciphertext3), ad).read(),
        plaintext)
    self.assertEqual(
        dec3.new_decrypting_stream(io.BytesIO(ciphertext3), ad).read(),
        plaintext)
    self.assertEqual(
        dec4.new_decrypting_stream(io.BytesIO(ciphertext3), ad).read(),
        plaintext)

    # 4 encrypts with the newer key. So 2, 3 and 4 can decrypt it, but not 1.
    ciphertext4 = enc4.new_encrypting_stream(io.BytesIO(plaintext), ad).read()
    with self.assertRaises(tink.TinkError):
      _ = dec1.new_decrypting_stream(io.BytesIO(ciphertext4), ad).read()
    self.assertEqual(
        dec2.new_decrypting_stream(io.BytesIO(ciphertext4), ad).read(),
        plaintext)
    self.assertEqual(
        dec3.new_decrypting_stream(io.BytesIO(ciphertext4), ad).read(),
        plaintext)
    self.assertEqual(
        dec4.new_decrypting_stream(io.BytesIO(ciphertext4), ad).read(),
        plaintext)

if __name__ == '__main__':
  absltest.main()
