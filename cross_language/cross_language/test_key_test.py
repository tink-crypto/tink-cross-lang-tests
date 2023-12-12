# Copyright 2023 Google LLC
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

from absl.testing import absltest

from tink.proto import tink_pb2
from cross_language import test_key


class TestKeyTest(absltest.TestCase):

  def test_construction_works(self):
    test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=True,
    )

  def test_to_string_works(self):
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_id=1234,
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=True,
    )
    self.assertIn('HmacKey', str(key))
    self.assertIn('some_test_name', str(key))

  def test_valid_true_works(self):
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_id=1234,
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=True,
    )
    self.assertTrue(key.supported_in('cc'))

  def test_valid_false_works(self):
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_id=1234,
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=False,
    )
    self.assertFalse(key.supported_in('cc'))

  def test_to_keyset_works(self):
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_material_type=tink_pb2.KeyData.KeyMaterialType.REMOTE,
        output_prefix_type=tink_pb2.OutputPrefixType.RAW,
        key_status=tink_pb2.KeyStatusType.DISABLED,
        valid=True,
    )
    keyset_bytes = key.as_serialized_keyset()
    keyset = tink_pb2.Keyset.FromString(keyset_bytes)
    self.assertGreater(keyset.primary_key_id, 0)
    self.assertLen(keyset.key, 1)
    self.assertEqual(
        keyset.key[0].key_data.type_url,
        'type.googleapis.com/google.crypto.tink.HmacKey',
    )
    self.assertEqual(keyset.key[0].key_data.value, b'some_serialized_value')
    self.assertEqual(
        keyset.key[0].key_data.key_material_type,
        tink_pb2.KeyData.KeyMaterialType.REMOTE,
    )
    self.assertEqual(keyset.key[0].status, tink_pb2.KeyStatusType.DISABLED)
    self.assertEqual(keyset.key[0].key_id, keyset.primary_key_id)
    self.assertEqual(
        keyset.key[0].output_prefix_type, tink_pb2.OutputPrefixType.RAW
    )

  def test_valid_false_works_with_invalid_keytype(self):
    """Setting valid=False works if non-existing key types are used.

    This because it should be possible to create TestKeys even for invalid
    type_urls. If valid=True is used this forces a lookup in the tink_config.
    This must be avoided if valid=False is used.
    """
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='some invalid type url',
        serialized_value=b'some_serialized_value',
        key_id=1234,
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=False,
    )
    keyset_bytes = key.as_serialized_keyset()
    keyset = tink_pb2.Keyset.FromString(keyset_bytes)
    self.assertGreater(keyset.primary_key_id, 0)
    self.assertLen(keyset.key, 1)
    self.assertEqual(
        keyset.key[0].key_data.type_url,
        'some invalid type url',
    )

  def test_setting_key_id_works(self):
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_id=1234,
        key_material_type=tink_pb2.KeyData.KeyMaterialType.REMOTE,
        output_prefix_type=tink_pb2.OutputPrefixType.RAW,
        key_status=tink_pb2.KeyStatusType.DISABLED,
        valid=True,
    )
    keyset_bytes = key.as_serialized_keyset()
    keyset = tink_pb2.Keyset.FromString(keyset_bytes)
    self.assertEqual(keyset.primary_key_id, 1234)
    self.assertLen(keyset.key, 1)
    self.assertEqual(keyset.key[0].key_id, 1234)

  def test_tags_default(self):
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=True,
    )
    self.assertEqual(key.tags(), [])

  def test_tags_explicit_empty(self):
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=True,
        tags=[],
    )
    self.assertEqual(key.tags(), [])

  def test_tags_works(self):
    key = test_key.TestKey(
        test_name='some_test_name',
        type_url='type.googleapis.com/google.crypto.tink.HmacKey',
        serialized_value=b'some_serialized_value',
        key_material_type=tink_pb2.KeyData.KeyMaterialType.SYMMETRIC,
        valid=True,
        tags=['these', 'are', 'tags'],
    )
    self.assertEqual(key.tags(), ['these', 'are', 'tags'])


if __name__ == '__main__':
  absltest.main()
