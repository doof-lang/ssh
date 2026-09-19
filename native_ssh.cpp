#include "native_ssh.hpp"

#include <libssh2.h>
#include <libssh2_sftp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace doof_ssh {
namespace {

std::once_flag libssh2_init_flag;
void ensure_libssh2() { std::call_once(libssh2_init_flag, [] { libssh2_init(0); }); }

#if defined(_WIN32)
using Socket = SOCKET;
constexpr Socket kInvalidSocket = INVALID_SOCKET;
void close_socket(Socket value) { closesocket(value); }
std::string socket_error() { return "socket error " + std::to_string(WSAGetLastError()); }
class Winsock { public: Winsock() : ready(WSAStartup(MAKEWORD(2, 2), &data) == 0) {} ~Winsock() { if (ready) WSACleanup(); } WSADATA data {}; bool ready; };
bool ensure_winsock() { static Winsock winsock; return winsock.ready; }
bool set_nonblocking(Socket value, bool enabled) {
    u_long mode = enabled ? 1 : 0;
    return ioctlsocket(value, FIONBIO, &mode) == 0;
}
#else
using Socket = int;
constexpr Socket kInvalidSocket = -1;
void close_socket(Socket value) { close(value); }
std::string socket_error() { return std::strerror(errno); }
bool set_nonblocking(Socket value, bool enabled) {
    const int flags = fcntl(value, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(value, F_SETFL, enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) == 0;
}
#endif

bool connect_with_timeout(Socket socket, const addrinfo* address, std::chrono::milliseconds timeout) {
    if (!set_nonblocking(socket, true)) return false;
    if (::connect(socket, address->ai_addr, static_cast<socklen_t>(address->ai_addrlen)) == 0) return set_nonblocking(socket, false);
    fd_set writable {};
    fd_set errors {};
    FD_SET(socket, &writable);
    FD_SET(socket, &errors);
    const auto count = std::max<int64_t>(0, timeout.count());
    timeval wait {};
    wait.tv_sec = count / 1000;
    wait.tv_usec = (count % 1000) * 1000;
#if defined(_WIN32)
    const int selected = select(0, nullptr, &writable, &errors, &wait);
#else
    const int selected = select(socket + 1, nullptr, &writable, &errors, &wait);
#endif
    int error = 0;
    socklen_t errorLength = sizeof(error);
    const bool connected = selected > 0 &&
        (FD_ISSET(socket, &writable) || FD_ISSET(socket, &errors)) &&
        getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &errorLength) == 0 && error == 0;
    if (!connected) {
#if defined(_WIN32)
        if (error != 0) WSASetLastError(error);
#else
        if (error != 0) errno = error;
#endif
        return false;
    }
    return set_nonblocking(socket, false);
}

std::string session_error(LIBSSH2_SESSION* session, const std::string& prefix) {
    char* message = nullptr;
    const int length = libssh2_session_last_error(session, &message, nullptr, 0);
    return prefix + (message && length > 0 ? ": " + std::string(message, static_cast<size_t>(length)) : "");
}

std::string sftp_error(LIBSSH2_SFTP* sftp, const std::string& prefix) {
    return prefix + " (SFTP status " + std::to_string(libssh2_sftp_last_error(sftp)) + ")";
}

bool hex_fingerprint_matches(const std::string& expected, const char* actual) {
    if (expected.size() != 64 || actual == nullptr) return false;
    static constexpr char hex[] = "0123456789abcdef";
    for (size_t index = 0; index < 32; ++index) {
        const uint8_t byte = static_cast<uint8_t>(actual[index]);
        const char high = static_cast<char>(std::tolower(static_cast<unsigned char>(expected[index * 2])));
        const char low = static_cast<char>(std::tolower(static_cast<unsigned char>(expected[index * 2 + 1])));
        if (high != hex[byte >> 4] || low != hex[byte & 0x0f]) return false;
    }
    return true;
}

std::string hex_fingerprint(const char* digest, size_t length) {
    static constexpr char hex[] = "0123456789abcdef";
    if (!digest) return "unavailable";
    std::string value;
    value.reserve(length * 2);
    for (size_t index = 0; index < length; ++index) {
        const uint8_t byte = static_cast<uint8_t>(digest[index]);
        value.push_back(hex[byte >> 4]);
        value.push_back(hex[byte & 0x0f]);
    }
    return value;
}

int known_host_key_type(int hostKeyType) {
    switch (hostKeyType) {
        case LIBSSH2_HOSTKEY_TYPE_RSA: return LIBSSH2_KNOWNHOST_KEY_SSHRSA;
        case LIBSSH2_HOSTKEY_TYPE_DSS: return LIBSSH2_KNOWNHOST_KEY_SSHDSS;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: return LIBSSH2_KNOWNHOST_KEY_ECDSA_256;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: return LIBSSH2_KNOWNHOST_KEY_ECDSA_384;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: return LIBSSH2_KNOWNHOST_KEY_ECDSA_521;
        case LIBSSH2_HOSTKEY_TYPE_ED25519: return LIBSSH2_KNOWNHOST_KEY_ED25519;
        default: return LIBSSH2_KNOWNHOST_KEY_UNKNOWN;
    }
}

constexpr std::string_view kDefaultHostKeyPreferences =
    "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256";

bool known_host_name_matches(const std::string& names, const std::string& host, int32_t port) {
    const std::string portSpecific = "[" + host + "]:" + std::to_string(port);
    size_t start = 0;
    while (start < names.size()) {
        const size_t end = names.find(',', start);
        const std::string name = names.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (name == host || name == portSpecific) return true;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return false;
}

void append_preference(std::vector<std::string>& preferences, const std::string& algorithm) {
    if (std::find(preferences.begin(), preferences.end(), algorithm) == preferences.end()) preferences.push_back(algorithm);
}

std::string known_host_preferences(const std::string& path, const std::string& host, int32_t port) {
    std::ifstream input(path);
    if (!input) return "";
    bool hasEd25519 = false;
    bool hasEcdsa256 = false;
    bool hasEcdsa384 = false;
    bool hasEcdsa521 = false;
    bool hasRsa = false;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string names;
        std::string algorithm;
        if (!(fields >> names) || names.empty() || names[0] == '#') continue;
        // Marked entries are policy records rather than ordinary host keys.
        if (names[0] == '@') { if (!(fields >> names)) continue; }
        if (!(fields >> algorithm) || !known_host_name_matches(names, host, port)) continue;
        if (algorithm == "ssh-ed25519") hasEd25519 = true;
        else if (algorithm == "ecdsa-sha2-nistp256") hasEcdsa256 = true;
        else if (algorithm == "ecdsa-sha2-nistp384") hasEcdsa384 = true;
        else if (algorithm == "ecdsa-sha2-nistp521") hasEcdsa521 = true;
        else if (algorithm == "ssh-rsa") hasRsa = true;
    }
    std::vector<std::string> preferences;
    if (hasEd25519) append_preference(preferences, "ssh-ed25519");
    if (hasEcdsa256) append_preference(preferences, "ecdsa-sha2-nistp256");
    if (hasEcdsa384) append_preference(preferences, "ecdsa-sha2-nistp384");
    if (hasEcdsa521) append_preference(preferences, "ecdsa-sha2-nistp521");
    // OpenSSH stores RSA host keys as ssh-rsa even when RSA-SHA2 signatures
    // are negotiated. Never re-enable the legacy SHA-1 ssh-rsa method.
    if (hasRsa) {
        append_preference(preferences, "rsa-sha2-512");
        append_preference(preferences, "rsa-sha2-256");
    }
    std::string value;
    for (const std::string& preference : preferences) {
        if (!value.empty()) value += ",";
        value += preference;
    }
    return value;
}

} // namespace

class NativeSshClient::Impl {
public:
    Socket socket = kInvalidSocket;
    LIBSSH2_SESSION* session = nullptr;
    LIBSSH2_SFTP* sftp = nullptr;
    std::string out;
    std::string err;
    ~Impl() {
        if (sftp) libssh2_sftp_shutdown(sftp);
        if (session) { libssh2_session_disconnect(session, "closed"); libssh2_session_free(session); }
        if (socket != kInvalidSocket) close_socket(socket);
    }
};

NativeSshClient::NativeSshClient() : impl_(std::make_unique<Impl>()) {}
NativeSshClient::~NativeSshClient() = default;

doof::Result<std::shared_ptr<NativeSshClient>, std::string> NativeSshClient::connect(
    const std::string& host, int32_t port, const std::string& username, const std::optional<std::string>& password,
    const std::optional<std::string>& privateKeyPath, const std::optional<std::string>& privateKeyPassphrase,
    const std::optional<std::string>& knownHostsPath, const std::optional<std::string>& hostKeySha256,
    int64_t waitNanos, int32_t timeoutMs
) {
    if (host.empty() || username.empty() || port < 1 || port > 65535) return { doof::Failure<std::string> { "invalid SSH host, username, or port" } };
    ensure_libssh2();
#if defined(_WIN32)
    if (!ensure_winsock()) return { doof::Failure<std::string> { "could not initialize Winsock" } };
#endif
    const auto retryBudget = std::chrono::nanoseconds(std::max<int64_t>(0, waitNanos));
    const auto deadline = std::chrono::steady_clock::now() + retryBudget;
    const std::string service = std::to_string(port);
    Socket socket = kInvalidSocket;
    std::string lastError = "could not resolve SSH host";
    for (;;) {
        addrinfo hints {}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
        addrinfo* addresses = nullptr;
        if (getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses) == 0) {
            for (addrinfo* address = addresses; address; address = address->ai_next) {
                socket = ::socket(address->ai_family, address->ai_socktype, address->ai_protocol);
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::max(std::chrono::steady_clock::duration::zero(), deadline - std::chrono::steady_clock::now()));
                if (socket != kInvalidSocket && connect_with_timeout(socket, address, std::min(std::chrono::milliseconds(250), remaining))) break;
                if (socket != kInvalidSocket) { lastError = socket_error(); close_socket(socket); socket = kInvalidSocket; }
            }
            freeaddrinfo(addresses);
        }
        if (socket != kInvalidSocket || std::chrono::steady_clock::now() >= deadline) break;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (remaining.count() > 0) std::this_thread::sleep_for(std::min(std::chrono::milliseconds(100), remaining));
    }
    if (socket == kInvalidSocket) return { doof::Failure<std::string> { "could not connect to SSH host after waiting " +
        std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(retryBudget).count()) + "ms: " + lastError } };
    auto client = std::shared_ptr<NativeSshClient>(new NativeSshClient());
    client->impl_->socket = socket;
    client->impl_->session = libssh2_session_init_ex(nullptr, nullptr, nullptr, nullptr);
    if (!client->impl_->session) return { doof::Failure<std::string> { "could not initialize libssh2 session" } };
    // For ordinary (non-hashed) records, negotiate a key algorithm already
    // trusted for this exact host first. The raw key remains mandatory below.
    const std::string trustedPreferences = knownHostsPath
        ? known_host_preferences(*knownHostsPath, host, port)
        : "";
    const std::string& hostKeyPreferences = trustedPreferences.empty()
        ? std::string(kDefaultHostKeyPreferences)
        : trustedPreferences;
    if (libssh2_session_method_pref(client->impl_->session, LIBSSH2_METHOD_HOSTKEY,
        hostKeyPreferences.c_str()) != 0) {
        return { doof::Failure<std::string> { session_error(client->impl_->session, "could not set SSH host-key preferences") } };
    }
    libssh2_session_set_timeout(client->impl_->session, timeoutMs > 0 ? timeoutMs : 30000);
    if (libssh2_session_handshake(client->impl_->session, socket) != 0) return { doof::Failure<std::string> { session_error(client->impl_->session, "SSH handshake failed") } };

    const char* hostKey = nullptr; size_t hostKeyLength = 0; int hostKeyType = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    hostKey = libssh2_session_hostkey(client->impl_->session, &hostKeyLength, &hostKeyType);
    bool verified = false;
    const char* hostKeySha256Digest = libssh2_hostkey_hash(client->impl_->session, LIBSSH2_HOSTKEY_HASH_SHA256);
    if (hostKeySha256 && hex_fingerprint_matches(*hostKeySha256, hostKeySha256Digest)) verified = true;
    int knownHostCheck = LIBSSH2_KNOWNHOST_CHECK_NOTFOUND;
    if (!verified && knownHostsPath && hostKey) {
        LIBSSH2_KNOWNHOSTS* known = libssh2_knownhost_init(client->impl_->session);
        if (known) {
            const int read = libssh2_knownhost_readfile(known, knownHostsPath->c_str(), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
            struct libssh2_knownhost* match = nullptr;
            if (read < 0) {
                libssh2_knownhost_free(known);
                return { doof::Failure<std::string> { "could not read or parse SSH known-hosts file: " + *knownHostsPath } };
            }
            // The raw key comparison is the security decision. Deliberately
            // omit a key-type restriction: libssh2's reported host-key type
            // and its known_hosts parser have differed across releases for
            // newer algorithms, which can otherwise reject an identical key.
            knownHostCheck = libssh2_knownhost_checkp(known, host.c_str(), port, hostKey, hostKeyLength,
                LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW, &match);
            verified = knownHostCheck == LIBSSH2_KNOWNHOST_CHECK_MATCH;
            libssh2_knownhost_free(known);
        }
    }
    if (!verified) return { doof::Failure<std::string> {
        "SSH host key was not verified (known-hosts result " + std::to_string(knownHostCheck) +
        ", algorithm " + std::to_string(hostKeyType) +
        ", SHA-256 hex " + hex_fingerprint(hostKeySha256Digest, 32) + ")"
    } };
    int auth = -1;
    if (privateKeyPath) auth = libssh2_userauth_publickey_fromfile_ex(client->impl_->session, username.c_str(), static_cast<unsigned int>(username.size()), nullptr, privateKeyPath->c_str(), privateKeyPassphrase ? privateKeyPassphrase->c_str() : nullptr);
    else if (password) auth = libssh2_userauth_password_ex(client->impl_->session, username.c_str(), static_cast<unsigned int>(username.size()), password->c_str(), static_cast<unsigned int>(password->size()), nullptr);
    if (auth != 0) return { doof::Failure<std::string> { session_error(client->impl_->session, "SSH authentication failed") } };
    return { doof::Success<std::shared_ptr<NativeSshClient>> { client } };
}

doof::Result<int32_t, std::string> NativeSshClient::run(const std::string& command, int32_t timeoutMs) {
    if (!impl_->session) return { doof::Failure<std::string> { "SSH client is closed" } };
    impl_->out.clear(); impl_->err.clear();
    libssh2_session_set_timeout(impl_->session, timeoutMs > 0 ? timeoutMs : 30000);
    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(impl_->session);
    if (!channel) return { doof::Failure<std::string> { session_error(impl_->session, "could not open SSH channel") } };
    if (libssh2_channel_exec(channel, command.c_str()) != 0) { libssh2_channel_free(channel); return { doof::Failure<std::string> { session_error(impl_->session, "could not execute SSH command") } }; }
    std::array<char, 4096> buffer {};
    for (;;) { const ssize_t count = libssh2_channel_read_ex(channel, 0, buffer.data(), buffer.size()); if (count > 0) impl_->out.append(buffer.data(), static_cast<size_t>(count)); else break; }
    for (;;) { const ssize_t count = libssh2_channel_read_ex(channel, 1, buffer.data(), buffer.size()); if (count > 0) impl_->err.append(buffer.data(), static_cast<size_t>(count)); else break; }
    libssh2_channel_close(channel);
    const int status = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);
    return { doof::Success<int32_t> { status } };
}

doof::Result<void, std::string> NativeSshClient::openSftp() {
    if (!impl_->session) return { doof::Failure<std::string> { "SSH client is closed" } };
    if (impl_->sftp) return { doof::Success<void> { } };
    impl_->sftp = libssh2_sftp_init(impl_->session);
    if (!impl_->sftp) return { doof::Failure<std::string> { session_error(impl_->session, "could not initialize SFTP") } };
    return { doof::Success<void> {  } };
}

doof::Result<NativeSshClient::Bytes, std::string> NativeSshClient::readSftpFile(const std::string& path, int64_t maximumBytes) {
    if (!impl_->sftp) return { doof::Failure<std::string> { "SFTP client is closed" } };
    if (path.empty() || path.find('\0') != std::string::npos || maximumBytes < 0) return { doof::Failure<std::string> { "invalid SFTP path or maximumBytes" } };
    LIBSSH2_SFTP_ATTRIBUTES attributes {};
    if (libssh2_sftp_stat(impl_->sftp, path.c_str(), &attributes) != 0) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not stat SFTP file") } };
    if ((attributes.flags & LIBSSH2_SFTP_ATTR_SIZE) && attributes.filesize > static_cast<libssh2_uint64_t>(maximumBytes)) {
        return { doof::Failure<std::string> { "SFTP file exceeds maximumBytes" } };
    }
    LIBSSH2_SFTP_HANDLE* file = libssh2_sftp_open(impl_->sftp, path.c_str(), LIBSSH2_FXF_READ, 0);
    if (!file) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not open SFTP file") } };
    auto data = std::make_shared<std::vector<uint8_t>>();
    std::array<char, 65536> buffer {};
    while (true) {
        const ssize_t count = libssh2_sftp_read(file, buffer.data(), buffer.size());
        if (count > 0) {
            if (static_cast<uint64_t>(count) > static_cast<uint64_t>(maximumBytes) - data->size()) {
                libssh2_sftp_close(file);
                return { doof::Failure<std::string> { "SFTP file exceeds maximumBytes" } };
            }
            data->insert(data->end(), buffer.begin(), buffer.begin() + count);
            continue;
        }
        if (count == 0) break;
        libssh2_sftp_close(file);
        return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not read SFTP file") } };
    }
    if (libssh2_sftp_close(file) != 0) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not close SFTP file") } };
    return { doof::Success<Bytes> { data } };
}

doof::Result<void, std::string> NativeSshClient::writeSftpFile(const std::string& path, const Bytes& data) {
    if (!impl_->sftp) return { doof::Failure<std::string> { "SFTP client is closed" } };
    if (path.empty() || path.find('\0') != std::string::npos) return { doof::Failure<std::string> { "invalid SFTP path" } };
    LIBSSH2_SFTP_HANDLE* file = libssh2_sftp_open(impl_->sftp, path.c_str(), LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
        LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH);
    if (!file) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not open SFTP file for writing") } };
    size_t offset = 0;
    while (offset < data->size()) {
        const ssize_t count = libssh2_sftp_write(file, reinterpret_cast<const char*>(data->data() + offset), data->size() - offset);
        if (count <= 0) { libssh2_sftp_close(file); return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not write SFTP file") } }; }
        offset += static_cast<size_t>(count);
    }
    if (libssh2_sftp_close(file) != 0) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not close SFTP file") } };
    return { doof::Success<void> {} };
}

doof::Result<NativeSshClient::Strings, std::string> NativeSshClient::listSftpDirectory(const std::string& path) {
    if (!impl_->sftp) return { doof::Failure<std::string> { "SFTP client is closed" } };
    if (path.empty() || path.find('\0') != std::string::npos) return { doof::Failure<std::string> { "invalid SFTP path" } };
    LIBSSH2_SFTP_HANDLE* directory = libssh2_sftp_opendir(impl_->sftp, path.c_str());
    if (!directory) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not open SFTP directory") } };
    auto names = std::make_shared<std::vector<std::string>>();
    std::array<char, 4096> buffer {};
    while (true) {
        LIBSSH2_SFTP_ATTRIBUTES attributes {};
        const int count = libssh2_sftp_readdir(directory, buffer.data(), buffer.size(), &attributes);
        if (count > 0) {
            std::string name(buffer.data(), static_cast<size_t>(count));
            if (name != "." && name != "..") names->push_back(std::move(name));
            continue;
        }
        if (count == 0) break;
        libssh2_sftp_closedir(directory);
        return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not read SFTP directory") } };
    }
    if (libssh2_sftp_closedir(directory) != 0) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not close SFTP directory") } };
    return { doof::Success<Strings> { names } };
}

doof::Result<void, std::string> NativeSshClient::makeSftpDirectory(const std::string& path) {
    if (!impl_->sftp) return { doof::Failure<std::string> { "SFTP client is closed" } };
    if (path.empty() || path.find('\0') != std::string::npos) return { doof::Failure<std::string> { "invalid SFTP path" } };
    if (libssh2_sftp_mkdir(impl_->sftp, path.c_str(), LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IXGRP | LIBSSH2_SFTP_S_IROTH | LIBSSH2_SFTP_S_IXOTH) != 0) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not create SFTP directory") } };
    return { doof::Success<void> {} };
}

doof::Result<void, std::string> NativeSshClient::removeSftpFile(const std::string& path) {
    if (!impl_->sftp) return { doof::Failure<std::string> { "SFTP client is closed" } };
    if (libssh2_sftp_unlink(impl_->sftp, path.c_str()) != 0) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not remove SFTP file") } };
    return { doof::Success<void> {} };
}

doof::Result<void, std::string> NativeSshClient::removeSftpDirectory(const std::string& path) {
    if (!impl_->sftp) return { doof::Failure<std::string> { "SFTP client is closed" } };
    if (libssh2_sftp_rmdir(impl_->sftp, path.c_str()) != 0) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not remove SFTP directory") } };
    return { doof::Success<void> {} };
}

doof::Result<void, std::string> NativeSshClient::renameSftpPath(const std::string& source, const std::string& destination, bool overwrite) {
    if (!impl_->sftp) return { doof::Failure<std::string> { "SFTP client is closed" } };
    const long flags = overwrite ? LIBSSH2_SFTP_RENAME_OVERWRITE : 0;
    if (libssh2_sftp_rename_ex(impl_->sftp, source.c_str(), static_cast<unsigned int>(source.size()), destination.c_str(), static_cast<unsigned int>(destination.size()), flags) != 0) return { doof::Failure<std::string> { sftp_error(impl_->sftp, "could not rename SFTP path") } };
    return { doof::Success<void> {} };
}

void NativeSshClient::closeSftp() {
    if (impl_->sftp) { libssh2_sftp_shutdown(impl_->sftp); impl_->sftp = nullptr; }
}

std::string NativeSshClient::stdout() const { return impl_->out; }
std::string NativeSshClient::stderr() const { return impl_->err; }
void NativeSshClient::close() { impl_.reset(new Impl()); }

} // namespace doof_ssh
