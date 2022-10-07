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
"""Tests for _helpers."""

from absl.testing import absltest
from tink import aead
from tink import hybrid
from tink import mac

from tink.proto import tink_pb2
from tink_config import _helpers
from util import test_keys


def setUpModule():
  aead.register()
  mac.register()


class HelpersTest(absltest.TestCase):

  def test_get_all_key_types(self):
    self.assertNotEmpty(_helpers.all_key_types())

  def test_get_aead_key_types(self):
    self.assertNotEmpty(_helpers.key_types_for_primitive(aead.Aead))

  def test_key_type_from_type_url(self):
    self.assertEqual(
        _helpers.key_type_from_type_url(
            'type.googleapis.com/google.crypto.tink.AesGcmKey'), 'AesGcmKey')

  def test_key_type_from_type_url_wrong_prefix_throws(self):
    with self.assertRaises(ValueError):
      _helpers.key_type_from_type_url(
          'type.googleapis.com/google.crypto.tinkAesGcmKey')

  def test_key_type_from_type_url_wrong_key_type_throws(self):
    with self.assertRaises(ValueError):
      _helpers.key_type_from_type_url(
          'type.googleapis.com/google.crypto.tink.InvalidKeyType29981')

  def test_supported_languages_for_key_type(self):
    self.assertCountEqual(
        _helpers.supported_languages_for_key_type('AesGcmKey'),
        ['cc', 'java', 'go', 'python'])

  def test_supported_languages_for_key_type_invalid(self):
    with self.assertRaises(ValueError):
      _helpers.supported_languages_for_key_type('InvalidKeyType21b9a1')

  def test_supported_languages_for_primitive(self):
    self.assertCountEqual(
        _helpers.supported_languages_for_primitive(aead.Aead),
        ['cc', 'java', 'go', 'python'])

  def test_supported_languages_for_primitive_invalid(self):
    with self.assertRaises(KeyError):
      _helpers.supported_languages_for_primitive('not a primitive, a string')

  def test_all_primitives(self):
    self.assertContainsSubset(
        [aead.Aead, hybrid.HybridEncrypt, hybrid.HybridEncrypt],
        _helpers.all_primitives())

  def test_primitive_for_keytype(self):
    self.assertEqual(_helpers.primitive_for_keytype('AesGcmKey'), aead.Aead)

  def test_primitive_for_keytype_throws_invalid(self):
    with self.assertRaises(ValueError):
      _helpers.primitive_for_keytype('InvalidKeyType776611')

  def test_is_asymmetric_public_key_primitive(self):
    self.assertFalse(_helpers.is_asymmetric_public_key_primitive(aead.Aead))
    self.assertFalse(
        _helpers.is_asymmetric_public_key_primitive(hybrid.HybridDecrypt))
    self.assertTrue(
        _helpers.is_asymmetric_public_key_primitive(hybrid.HybridEncrypt))

  def test_get_private_key_primitive(self):
    self.assertEqual(
        _helpers.get_private_key_primitive(hybrid.HybridEncrypt),
        hybrid.HybridDecrypt)

  def test_keyset_supported_true(self):
    keyset = test_keys.some_keyset_for_primitive(aead.Aead)
    self.assertTrue(_helpers.keyset_supported(keyset, aead.Aead, 'python'))

  def test_keyset_supported_keyset_wrong_primitive_false(self):
    keyset = test_keys.some_keyset_for_primitive(aead.Aead)
    self.assertFalse(_helpers.keyset_supported(keyset, mac.Mac, 'python'))

  def test_keyset_supported_keyset_wrong_language_false(self):
    keyset = test_keys.some_keyset_for_primitive(aead.Aead)
    self.assertFalse(
        _helpers.keyset_supported(keyset, aead.Aead, 'non-existing-language'))

  def test_keyset_two_keys_supported_true(self):
    keyset = test_keys.some_keyset_for_primitive(aead.Aead)
    parsed_keyset = tink_pb2.Keyset.FromString(keyset)
    key0 = parsed_keyset.key[0]
    parsed_keyset.key.append(key0)
    parsed_keyset.key[1].key_id += 1
    self.assertTrue(
        _helpers.keyset_supported(parsed_keyset.SerializeToString(), aead.Aead,
                                  'python'))

  def test_keyset_two_keys_unsupported_false(self):
    keyset0 = test_keys.some_keyset_for_primitive(aead.Aead)
    keyset1 = test_keys.some_keyset_for_primitive(mac.Mac)
    parsed_keyset0 = tink_pb2.Keyset.FromString(keyset0)
    parsed_keyset1 = tink_pb2.Keyset.FromString(keyset1)
    parsed_keyset0.key.append(parsed_keyset1.key[0])
    self.assertFalse(
        _helpers.keyset_supported(parsed_keyset0.SerializeToString(), aead.Aead,
                                  'python'))

if __name__ == '__main__':
  absltest.main()
