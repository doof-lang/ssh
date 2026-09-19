#pragma once

#include "doof_runtime.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace doof_ssh {

class NativeSshClient {
public:
    using Bytes = std::shared_ptr<std::vector<uint8_t>>;
    using Strings = std::shared_ptr<std::vector<std::string>>;
    static doof::Result<std::shared_ptr<NativeSshClient>, std::string> connect(
        const std::string& host, int32_t port, const std::string& username,
        const std::optional<std::string>& password, const std::optional<std::string>& privateKeyPath,
        const std::optional<std::string>& privateKeyPassphrase, const std::optional<std::string>& knownHostsPath,
        const std::optional<std::string>& hostKeySha256, int64_t waitNanos, int32_t timeoutMs
    );
    ~NativeSshClient();
    doof::Result<int32_t, std::string> run(const std::string& command, int32_t timeoutMs);
    doof::Result<void, std::string> openSftp();
    doof::Result<Bytes, std::string> readSftpFile(const std::string& path, int64_t maximumBytes);
    doof::Result<void, std::string> writeSftpFile(const std::string& path, const Bytes& data);
    doof::Result<Strings, std::string> listSftpDirectory(const std::string& path);
    doof::Result<void, std::string> makeSftpDirectory(const std::string& path);
    doof::Result<void, std::string> removeSftpFile(const std::string& path);
    doof::Result<void, std::string> removeSftpDirectory(const std::string& path);
    doof::Result<void, std::string> renameSftpPath(const std::string& source, const std::string& destination, bool overwrite);
    void closeSftp();
    std::string stdout() const;
    std::string stderr() const;
    void close();

private:
    NativeSshClient();
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace doof_ssh
