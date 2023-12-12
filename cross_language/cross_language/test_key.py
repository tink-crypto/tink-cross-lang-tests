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

"""Provides TestKey objects to store keys in tests."""

import random
from typing import Optional, List

from tink.proto import tink_pb2
from cross_language import tink_config


def _languages_for(type_url: str) -> List[str]:
  key_type = tink_config.key_type_from_type_url(type_url)
  return tink_config.supported_languages_for_key_type(key_type)


class TestKey:
  """Stores a key for a test.

  This basically represents what is in the Keyset.Key proto. However, it is
  somewhat more flexible, since in the tests we also want to store invalid keys.
  Hence, for example, we allow the type url to be an arbitrary string, and the
  serialized_value to be an arbitrary string of bytes.
  """

  def __init__(
      self,
      *,
      test_name: str,
      type_url: str,
      serialized_value: bytes,
      key_material_type: tink_pb2.KeyData.KeyMaterialType,
      valid: bool,
      key_id: Optional[int] = None,
      output_prefix_type: tink_pb2.OutputPrefixType = tink_pb2.OutputPrefixType.TINK,
      key_status: tink_pb2.KeyStatusType = tink_pb2.KeyStatusType.ENABLED,
      tags: Optional[List[str]] = None,
  ):
    """Creates a new TestKey object.

    Args:
      test_name: A human understandable name given to this key. Tests using a
        TestKey can expose this to the user in the logs (most easily by
        converting it to a string with str(test_key)).
      type_url: The type_url for Keyset.Key.KeyData.type_url
      serialized_value: The value for Keyset.Key.KeyData.value
      key_material_type: The value for Keyset.Key.KeyData.key_material_type
      valid: Denotes whether this key is valid or invalid.
      key_id (optional): The value which will go into Keyset.Key.key_id. Random
        if not set.
      output_prefix_type (optional): The value for Keyset.Key.output_prefix_type
      key_status (optional): The value for Keyset.Key.key_status
      tags (optional): A list of strings which will be available via tags()
    """
    key_id = random.randint(0, 2**32) if key_id is None else key_id
    self._supported_languages = _languages_for(type_url) if valid else []

    self._name = test_name
    self._key = tink_pb2.Keyset.Key(
        key_data=tink_pb2.KeyData(
            type_url=type_url,
            value=serialized_value,
            key_material_type=key_material_type,
        ),
        status=key_status,
        key_id=key_id,
        output_prefix_type=output_prefix_type,
    )
    self._tags = tags if tags else []

  def supported_in(self, lang: str) -> bool:
    return lang in self._supported_languages

  def tags(self) -> List[str]:
    return self._tags

  def __str__(self) -> str:
    """Returns the key type and name of this key."""
    key_type = tink_config.key_type_from_type_url(self._key.key_data.type_url)
    return key_type + ":" + self._name

  def as_serialized_keyset(self) -> bytes:
    """Embeds this key in a Keyset and returns the serialization of it."""
    return tink_pb2.Keyset(
        primary_key_id=self._key.key_id,
        key=[self._key],
    ).SerializeToString()
