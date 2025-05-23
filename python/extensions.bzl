"""Tink testing_python Bazel module extensions."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _envoy_api_impl(_ctx):
    http_archive(
        name = "envoy_api",
        sha256 = "aed4389a9cf7777df7811185770dca7352f19a2fd68a41ae04e47071dada31eb",
        strip_prefix = "data-plane-api-88a37373e3cb5e1ab09e75dfb302b083168e6654",
        urls = [
            "https://storage.googleapis.com/grpc-bazel-mirror/github.com/envoyproxy/data-plane-api/archive/88a37373e3cb5e1ab09e75dfb302b083168e6654.tar.gz",
            "https://github.com/envoyproxy/data-plane-api/archive/88a37373e3cb5e1ab09e75dfb302b083168e6654.tar.gz",
        ],
    )

envoy_api_extension = module_extension(
    implementation = _envoy_api_impl,
)
