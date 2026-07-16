#include "hns_browser.h"

#include <cstddef>
#include <cstdint>
#include <type_traits>

static_assert(HNS_BROWSER_ABI_VERSION == 1u);
static_assert(std::is_standard_layout_v<HnsBrowserSlice>);
static_assert(std::is_standard_layout_v<HnsBrowserBuffer>);
static_assert(sizeof(HnsBrowserRuntimeHandle) == sizeof(std::uint64_t));
static_assert(sizeof(HnsBrowserProxyHandle) == sizeof(std::uint64_t));

int main() {
    auto *abiVersion = &hns_browser_abi_version;
    auto *runtimeCreate = &hns_browser_runtime_create;
    auto *proxyStart = &hns_browser_proxy_start;
    auto *canonicalHost = &hns_browser_canonical_host;
    auto *proxyStop = &hns_browser_proxy_request_stop;
    (void)abiVersion;
    (void)runtimeCreate;
    (void)proxyStart;
    (void)canonicalHost;
    (void)proxyStop;
    return 0;
}
