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
"""Helper functions to access the information in this module.
"""

from typing import Any, Iterable, List

from tink.proto import tink_pb2
from tink_config import _key_types

_TYPE_URL_PREFIX = 'type.googleapis.com/google.crypto.tink.'


def all_key_types() -> List[str]:
  """Returns all key types which Tink currently knows in short format.

  The related TypeUrl equals the short format returned here, but prefixed with
  type.googleapis.com/google.crypto.tink.
  """
  result = []
  for key_types_for_single_primitive in _key_types.KEY_TYPES.values():
    result += key_types_for_single_primitive
  return result


def key_types_for_primitive(p: Any) -> List[str]:
  """Returns all key types for the given primitive which Tink currently has.

  The related TypeUrl equals the short format returned here, but prefixed with
  type.googleapis.com/google.crypto.tink.
  Args:
    p: The class of the primitive (e.g. tink.Aead)
  Returns:
    The list of key types (e.g. ['AesGcmKey', 'AesEaxKey'])
  """
  return list(_key_types.KEY_TYPES[p])


def key_type_from_type_url(type_url: str) -> str:
  """Returns the key type from a given TypeUrl.

  If the TypeUrl is invalid throws an exception.
  Args:
    type_url: For example 'type.googleapis.com/google.crypto.tink.AesGcmKey'
  Returns:
    The stripped version (e.g. AesGcmKey)
  Raises:
    ValueError if the type url is unknown or in a bad format.
  """
  if not type_url.startswith(_TYPE_URL_PREFIX):
    raise ValueError('Invalid type_url: ' + type_url)
  # removeprefix does not yet exist in all our supported python versions.
  key_type = type_url[len(_TYPE_URL_PREFIX):]
  if key_type not in all_key_types():
    raise ValueError('key type unknown: ' + key_type)
  return key_type


def supported_languages_for_key_type(key_type: str) -> List[str]:
  """Returns the list of supported languages for a given KeyType.

    Throws an except if the key type is unkonwn.
  Args:
    key_type: The shortened type URL (e.g. 'AesGcmKey')
  Returns:
    The list of languages which this key type supportes.
  Raises:
    ValueError if the key type is unknown.
  """
  if key_type not in all_key_types():
    raise ValueError('key_type unknown: ' + key_type)
  return _key_types.SUPPORTED_LANGUAGES[key_type]


def supported_languages_for_primitive(p: Any) -> List[str]:
  """Returns the list of languages which support a primitive.

    Throws an except if the key type is unkonwn.
  Args:
    p: The Primitive
  Returns:
    The list of languages which this primitive supportes.
  Raises:
    ValueError if the key type is unknown.
  """
  result = set()
  for key_type in key_types_for_primitive(p):
    result.update(set(supported_languages_for_key_type(key_type)))
  return list(result)


def all_primitives() -> Iterable[Any]:
  """Returns all the primitive types (such as tink.aead.Aead)."""
  return [p for p, _ in _key_types.KEY_TYPES.items()]


def primitive_for_keytype(key_type: str) -> Any:
  """Returns the primitive for the given key type."""

  for p, key_types in _key_types.KEY_TYPES.items():
    if key_type in key_types:
      return p
  raise ValueError('Unknown key type: ' + key_type)


def is_asymmetric_public_key_primitive(p: Any) -> bool:
  """Returns true iff this p is the public part of an asymmetric scheme."""
  return p in _key_types.PRIVATE_TO_PUBLIC_PRIMITIVE.values()


def get_private_key_primitive(p: Any) -> Any:
  """Returns the private primitive corresponding to this public part."""
  inverted = {v: k for (k, v) in _key_types.PRIVATE_TO_PUBLIC_PRIMITIVE.items()}
  return inverted[p]


def _key_types_in_keyset(keyset: bytes) -> List[str]:
  parsed_keyset = tink_pb2.Keyset.FromString(keyset)
  type_urls = [k.key_data.type_url for k in parsed_keyset.key]
  return [key_type_from_type_url(t) for t in type_urls]


def keyset_supported(keyset: bytes, p: Any, lang: str) -> bool:
  """Checks if the given keyset can be instantiated as 'p' in the 'lang'.

  Returns true if it is expected that the keyset can be instantiated in language
  'lang', according to the current configuration stored in tink_config. This
  only looks at the key types in the keyset, and does not check if the keys
  themselves are valid. It also does not check that the keyset is valid.

  Args:
    keyset: The serialized keyset
    p: The primitive class, e.g. aead.Aead
    lang: The language, e.g. 'python' or 'java'.

  Returns:
    True iff all key types are for this primitive and supported in the given
    language.
  """

  key_types = _key_types_in_keyset(keyset)
  for key_type in key_types:
    if primitive_for_keytype(key_type) != p:
      return False
    if lang not in supported_languages_for_key_type(key_type):
      return False
  return True
