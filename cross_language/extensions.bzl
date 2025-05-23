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

def _portpicker_impl(_ctx):
    http_archive(
        name = "org_python_pypi_portpicker",
        build_file = "external/portpicker.BUILD.bazel",
        sha256 = "c55683ad725f5c00a41bc7db0225223e8be024b1fa564d039ed3390e4fd48fb3",
        strip_prefix = "portpicker-1.5.2/src",
        urls = [
            "https://files.pythonhosted.org/packages/3b/34/bfbd5236c7726452080a92a9f6ea9770cd65f51b05cef319ccb767ed32bf/portpicker-1.5.2.tar.gz",
        ],
    )

portpicker_extension = module_extension(
    implementation = _portpicker_impl,
)
