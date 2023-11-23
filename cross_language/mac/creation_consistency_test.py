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

import binascii
import itertools
from typing import Iterator, Tuple

from absl.testing import absltest
import tink

from tink.proto import tink_pb2
import tink_config
from mac import hmac_keys
from util import testing_servers


def setUpModule():
  tink.mac.register()
  testing_servers.start('mac.creation_consistency_test')


def tearDownModule():
  testing_servers.stop()


def to_hex(s: bytes) -> str:
  return binascii.hexlify(s).decode('utf-8')


def to_keyset(
    serialized_key: bytes,
    type_url: str,
    output_prefix_type: tink_pb2.OutputPrefixType,
) -> tink_pb2.Keyset:
  """Embeds a Key in a keyset."""
  return tink_pb2.Keyset(
      primary_key_id=1234,
      key=[
          tink_pb2.Keyset.Key(
              key_data=tink_pb2.KeyData(
                  type_url=type_url,
                  value=serialized_key,
                  key_material_type='SYMMETRIC',
              ),
              output_prefix_type=output_prefix_type,
              status=tink_pb2.KeyStatusType.ENABLED,
              key_id=1234,
          )
      ],
  )


def valid_mac_keys() -> Iterator[Tuple[str, bytes]]:
  for pair in hmac_keys.valid_hmac_keys():
    yield pair


def invalid_mac_keys() -> Iterator[Tuple[str, bytes]]:
  for pair in hmac_keys.invalid_hmac_keys():
    yield pair


class CreationConsistencyTest(absltest.TestCase):
  """Tests creation consistency of Mac implementations in different languages.

  See https://developers.google.com/tink/design/consistency.
  """

  def test_supported_lang_valid_keys(self):
    """Tests: Creation consistency, supported languages, valid keys."""
    for type_url, key in valid_mac_keys():
      key_type = tink_config.key_type_from_type_url(type_url)
      for lang in tink_config.supported_languages_for_key_type(key_type):
        with self.subTest(lang + ', ' + key_type + ', Key: ' + to_hex(key)):
          keyset = to_keyset(key, type_url, tink_pb2.OutputPrefixType.TINK)
          testing_servers.remote_primitive(
              lang, keyset.SerializeToString(), tink.mac.Mac
          )

  def test_supported_lang_invalid_keys(self):
    """Tests: Creation consistency, supported languages, invalid keys."""
    for type_url, key in invalid_mac_keys():
      key_type = tink_config.key_type_from_type_url(type_url)
      for lang in tink_config.supported_languages_for_key_type(
          tink_config.key_type_from_type_url(type_url)
      ):
        with self.subTest(lang + ', ' + key_type + ', Key: ' + to_hex(key)):
          keyset = to_keyset(key, type_url, tink_pb2.OutputPrefixType.TINK)
          with self.assertRaises(tink.TinkError):
            testing_servers.remote_primitive(
                lang, keyset.SerializeToString(), tink.mac.Mac
            )

  def test_unsupported_lang(self):
    """Tests: Creation consistency, unsupported languages, all keys."""
    for type_url, key in itertools.chain(valid_mac_keys(), invalid_mac_keys()):
      key_type = tink_config.key_type_from_type_url(type_url)
      for lang in tink_config.unsupported_languages_for_key_type(key_type):
        with self.subTest(lang + ', ' + key_type + ', Key: ' + to_hex(key)):
          keyset = to_keyset(key, type_url, tink_pb2.OutputPrefixType.TINK)
          with self.assertRaises(tink.TinkError):
            testing_servers.remote_primitive(
                lang, keyset.SerializeToString(), tink.mac.Mac
            )


if __name__ == '__main__':
  absltest.main()
