# Copyright 2024 Google LLC
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
"""Cross-language tests for reading and writing encrypted keysets."""

from typing import Iterable, NamedTuple, Tuple

from absl.testing import absltest
from absl.testing import parameterized
import tink

from cross_language.util import testing_servers


def setUpModule() -> None:
  testing_servers.start('json_keyset_parsing')


def tearDownModule() -> None:
  testing_servers.stop()


class TestCase(NamedTuple):
  name: str
  valid: bool
  json_keyset: str
  # List of languages where either parsing a valid keyset fails or parsing
  # an invalid keyset does not fail.
  lang_exceptions: list[str] = []


TEST_CASES = [
    TestCase(
        name='normal',
        valid=True,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
    ),
    TestCase(
        name='with_unicode_char',
        valid=True,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcm🔑",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
        # RapidJson doesn't allow unicode chars.
        lang_exceptions=['cc'],
    ),
    TestCase(
        name='array_with_tailing_comma',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      },
    ]
}""",
    ),
    TestCase(
        name='object_with_tailing_comma',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED",
      }
    ]
}""",
    ),
    TestCase(
        name='without_primary_key_id',
        valid=False,
        json_keyset="""{
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
        lang_exceptions=['go', 'java'],
    ),
    TestCase(
        name='multiple_primary_keys',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      },
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLh=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
        lang_exceptions=['go', 'java', 'cc'],
    ),
    TestCase(
        name='keys_with_the_same_id',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      },
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLh=="
          },
          "outputPrefixType":"TINK",
          "keyId": 43,
          "status":"ENABLED"
      },
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLi=="
          },
          "outputPrefixType":"TINK",
          "keyId": 43,
          "status":"ENABLED"
      }
    ]
}""",
        lang_exceptions=['go', 'java', 'cc', 'python'],
    ),
    TestCase(
        name='with_duplicate_map_key',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg==",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLh=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
        # RapidJson allows duplicate map keys.
        lang_exceptions=['cc'],
    ),
    TestCase(
        name='with_missing_quotes',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":TINK,
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
    ),
    TestCase(
        name='with_primary_key_id_as_string',
        valid=False,
        json_keyset="""{
    "primaryKeyId": "42",
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
        lang_exceptions=['go', 'python'],
    ),
    TestCase(
        name='with_primary_key_id_as_float',
        valid=False,
        json_keyset="""{
    "primaryKeyId": "42.001",
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42.001,
          "status":"ENABLED"
      }
    ]
}""",
    ),
    TestCase(
        name='with_primary_key_id_as_huge_int',
        valid=False,
        json_keyset="""{
    "primaryKeyId": 123412341234123412312314312234122341234123412341231231,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 123412341234123412312314312234122341234123412341231231,
          "status":"ENABLED"
      }
    ]
}""",
    ),
    TestCase(
        name='with_primary_key_id_as_huge_int_with_exponent',
        valid=False,
        json_keyset="""{
    "primaryKeyId": 1e1000,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 1e1000,
          "status":"ENABLED"
      }
    ]
}""",
    ),
    TestCase(
        name='with_primary_key_id_as_bool',
        valid=False,
        json_keyset="""{
    "primaryKeyId":true,
    "key":[
      {
          "keyData":{
            "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
    ),
    TestCase(
        name='key_is_not_array',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":
      {
          "keyData":{
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
}""",
    ),
    TestCase(
        name='key_entry_is_not_object',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[true]
}""",
    ),
    TestCase(
        name='keydata_is_not_object',
        valid=False,
        json_keyset="""{
    "primaryKeyId":42,
    "key":[
      {
          "keyData":124,
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
    ),
    TestCase(
        name='type_url_is_not_string',
        valid=False,
        json_keyset="""{
    "primaryKeyId":true,
    "key":[
      {
          "keyData":{
            "typeUrl":true,
            "keyMaterialType":"SYMMETRIC",
            "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "outputPrefixType":"TINK",
          "keyId": 42,
          "status":"ENABLED"
      }
    ]
}""",
    ),
]


def valid_test_cases() -> Iterable[Tuple[str, str, str]]:
  for test_case in TEST_CASES:
    for lang in testing_servers.LANGUAGES:
      if test_case.valid and lang not in test_case.lang_exceptions:
        yield ('%s in %s' % (test_case.name, lang), lang, test_case.json_keyset)
      if not test_case.valid and lang in test_case.lang_exceptions:
        yield ('%s in %s' % (test_case.name, lang), lang, test_case.json_keyset)


def invalid_test_cases() -> Iterable[Tuple[str, str, str]]:
  for test_case in TEST_CASES:
    for lang in testing_servers.LANGUAGES:
      if not test_case.valid and lang not in test_case.lang_exceptions:
        yield ('%s in %s' % (test_case.name, lang), lang, test_case.json_keyset)
      if test_case.valid and lang in test_case.lang_exceptions:
        yield ('%s in %s' % (test_case.name, lang), lang, test_case.json_keyset)


class JsonKeysetParsing(parameterized.TestCase):

  @parameterized.named_parameters(valid_test_cases())
  def test_parse_valid(self, lang, json_keyset):
    _ = testing_servers.keyset_from_json(lang, json_keyset)

  @parameterized.named_parameters(invalid_test_cases())
  def test_parse_invalid(self, lang, json_keyset):
    with self.assertRaises(tink.TinkError):
      _ = testing_servers.keyset_from_json(lang, json_keyset)


if __name__ == '__main__':
  absltest.main()
