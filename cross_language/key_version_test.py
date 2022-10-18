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
"""Tests that keys with higher version numbers are rejected."""

from typing import Iterable

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead
from tink import daead
from tink import mac
from tink import prf

from tink.proto import aes_cmac_pb2
from tink.proto import aes_cmac_prf_pb2
from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import aes_eax_pb2
from tink.proto import aes_gcm_pb2
from tink.proto import aes_gcm_siv_pb2
from tink.proto import aes_siv_pb2
from tink.proto import chacha20_poly1305_pb2
from tink.proto import hkdf_prf_pb2
from tink.proto import hmac_pb2
from tink.proto import hmac_prf_pb2
from tink.proto import kms_aead_pb2
from tink.proto import kms_envelope_pb2
from tink.proto import tink_pb2
from tink.proto import xchacha20_poly1305_pb2

import tink_config
from util import testing_servers
from util import utilities


KEY_TYPE_TO_PROTO_CLASS = {
    'AesEaxKey': aes_eax_pb2.AesEaxKey,
    'AesGcmKey': aes_gcm_pb2.AesGcmKey,
    'AesGcmSivKey': aes_gcm_siv_pb2.AesGcmSivKey,
    'AesCtrHmacAeadKey': aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey,
    'ChaCha20Poly1305Key': chacha20_poly1305_pb2.ChaCha20Poly1305Key,
    'XChaCha20Poly1305Key': xchacha20_poly1305_pb2.XChaCha20Poly1305Key,
    'KmsAeadKey': kms_aead_pb2.KmsAeadKey,
    'KmsEnvelopeAeadKey': kms_envelope_pb2.KmsEnvelopeAeadKey,
    'AesCmacKey': aes_cmac_pb2.AesCmacKey,
    'HmacKey': hmac_pb2.HmacKey,
    'AesCmacPrfKey': aes_cmac_prf_pb2.AesCmacPrfKey,
    'HmacPrfKey': hmac_prf_pb2.HmacPrfKey,
    'HkdfPrfKey': hkdf_prf_pb2.HkdfPrfKey,
    'AesSivKey': aes_siv_pb2.AesSivKey,
}


def gen_inc_versions(keyset):
  """Parses keyset and generates modified keyset with incremented version."""
  keyset_proto = tink_pb2.Keyset.FromString(keyset)
  for key in keyset_proto.key:
    key_type = tink_config.key_type_from_type_url(key.key_data.type_url)
    key_class = KEY_TYPE_TO_PROTO_CLASS[key_type]

    default_val = key.key_data.value

    key_proto = key_class.FromString(default_val)
    key_proto.version = key_proto.version + 1
    key.key_data.value = key_proto.SerializeToString()
    yield keyset_proto.SerializeToString()

    if key_type == 'AesCtrHmacAeadKey':
      key_proto1 = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey.FromString(
          default_val)
      key_proto1.aes_ctr_key.version = key_proto1.aes_ctr_key.version + 1
      key.key_data.value = key_proto1.SerializeToString()
      yield keyset_proto.SerializeToString()

      key_proto2 = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey.FromString(
          default_val)
      key_proto2.hmac_key.version = key_proto2.hmac_key.version + 1
      key.key_data.value = key_proto2.SerializeToString()
      yield keyset_proto.SerializeToString()

    key.key_data.value = default_val


def test_cases(key_types: Iterable[str]):
  for key_type in key_types:
    for key_template_name in utilities.KEY_TEMPLATE_NAMES[key_type]:
      for lang in tink_config.supported_languages_for_key_type(key_type):
        yield (key_template_name, lang)


def setUpModule():
  aead.register()
  mac.register()
  daead.register()
  prf.register()
  testing_servers.start('key_version')


def tearDownModule():
  testing_servers.stop()


class KeyVersionTest(parameterized.TestCase):
  """These tests verify that keys with an unknown version are rejected.

  The tests first try out the unmodified key to make sure that it works. This is
  done to make sure that the failure of the modified key is really due to the
  incremented version.
  """

  @parameterized.parameters(
      test_cases(tink_config.key_types_for_primitive(aead.Aead)))
  def test_inc_version_aead(self, key_template_name, lang):
    """Increments the key version by one and checks they can't be used."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    _ = testing_servers.remote_primitive(lang, keyset,
                                         aead.Aead).encrypt(b'foo', b'bar')
    for keyset1 in gen_inc_versions(keyset):
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(lang, keyset1, aead.Aead)

  @parameterized.parameters(
      test_cases(tink_config.key_types_for_primitive(daead.DeterministicAead)))
  def test_inc_version_daead(self, key_template_name, lang):
    """Increments the key version by one and checks they can't be used."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    p = testing_servers.remote_primitive(lang, keyset, daead.DeterministicAead)
    _ = p.encrypt_deterministically(b'foo', b'bar')
    for keyset1 in gen_inc_versions(keyset):
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(lang, keyset1,
                                             daead.DeterministicAead)

  @parameterized.parameters(
      test_cases(tink_config.key_types_for_primitive(mac.Mac)))
  def test_inc_version_mac(self, key_template_name, lang):
    """Increments the key version by one and checks they can't be used."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    _ = testing_servers.remote_primitive(lang, keyset, mac.Mac)
    for keyset1 in gen_inc_versions(keyset):
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(lang, keyset1, mac.Mac)

  @parameterized.parameters(
      test_cases(tink_config.key_types_for_primitive(prf.PrfSet)))
  def test_inc_version_prf(self, key_template_name, lang):
    """Increments the key version by one and checks they can't be used."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    prf_set = testing_servers.remote_primitive(lang, keyset, prf.PrfSet)
    _ = prf_set.primary().compute(b'foo', 16)
    for keyset1 in gen_inc_versions(keyset):
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(lang, keyset1, prf.PrfSet)


if __name__ == '__main__':
  absltest.main()
