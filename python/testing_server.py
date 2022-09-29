# Copyright 2020 Google LLC
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
"""Tink Primitive Testing Service in Python."""

from concurrent import futures
import sys

from absl import app
from absl import flags
import grpc
from tink import aead
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead

from tink.testing import fake_kms
from proto import testing_api_pb2_grpc
import jwt_service
import services

from tink.integration import awskms
from tink.integration import gcpkms

FLAGS = flags.FLAGS

flags.DEFINE_integer('port', 10000, 'The port of the server.')
GCP_CREDENTIALS_PATH = flags.DEFINE_string(
    'gcp_credentials_path', '', 'Google Cloud KMS credentials path.')
GCP_KEY_URI = flags.DEFINE_string(
    'gcp_key_uri', '', 'Google Cloud KMS key URL of the form: '
    'gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*.')
AWS_CREDENTIALS_PATH = flags.DEFINE_string('aws_credentials_path', '',
                                           'AWS KMS credentials path.')
AWS_KEY_URI = flags.DEFINE_string(
    'aws_key_uri', '', 'AWS KMS key URL of the form: '
    'aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>.')


def init_tink() -> None:
  """Initializes Tink registering the required primitives."""
  aead.register()
  daead.register()
  hybrid.register()
  mac.register()
  prf.register()
  signature.register()
  streaming_aead.register()
  jwt.register_jwt_mac()
  jwt.register_jwt_signature()
  fake_kms.register_client()
  awskms.AwsKmsClient.register_client(
      key_uri=AWS_KEY_URI.value, credentials_path=AWS_CREDENTIALS_PATH.value)
  gcpkms.GcpKmsClient.register_client(
      key_uri=GCP_KEY_URI.value, credentials_path=GCP_CREDENTIALS_PATH.value)


def main(unused_argv):
  init_tink()

  server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
  testing_api_pb2_grpc.add_MetadataServicer_to_server(
      services.MetadataServicer(), server)
  testing_api_pb2_grpc.add_KeysetServicer_to_server(
      services.KeysetServicer(), server)
  testing_api_pb2_grpc.add_AeadServicer_to_server(
      services.AeadServicer(), server)
  testing_api_pb2_grpc.add_DeterministicAeadServicer_to_server(
      services.DeterministicAeadServicer(), server)
  testing_api_pb2_grpc.add_MacServicer_to_server(
      services.MacServicer(), server)
  testing_api_pb2_grpc.add_PrfSetServicer_to_server(services.PrfSetServicer(),
                                                    server)
  testing_api_pb2_grpc.add_HybridServicer_to_server(
      services.HybridServicer(), server)
  testing_api_pb2_grpc.add_SignatureServicer_to_server(
      services.SignatureServicer(), server)
  testing_api_pb2_grpc.add_StreamingAeadServicer_to_server(
      services.StreamingAeadServicer(), server)
  testing_api_pb2_grpc.add_JwtServicer_to_server(jwt_service.JwtServicer(),
                                                 server)
  used_port = server.add_secure_port('[::]:%d' % FLAGS.port,
                                     grpc.local_server_credentials())
  server.start()
  print('Server started on port ' + str(used_port))
  print(' (stderr) Server started on port ' + str(used_port), file=sys.stderr)
  server.wait_for_termination()


if __name__ == '__main__':
  app.run(main)
