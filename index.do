// A blocking SSH client backed by libssh2. Native methods are isolated so
// callers may use them from actors or async work without shared-state access.

import { Duration } from "std/time"

export class SshConnectOptions {
    readonly host: string
    readonly username: string
    readonly port: int = 22
    readonly password: string | none = none
    readonly privateKeyPath: string | none = none
    readonly privateKeyPassphrase: string | none = none
    // Supply one of these. Host verification is never implicit.
    readonly knownHostsPath: string | none = none
    // SHA-256 host-key fingerprint as 64 lowercase or uppercase hex digits.
    readonly hostKeySha256: string | none = none
    // Retry unavailable TCP endpoints for this long. This helps while a VM
    // starts or a machine wakes from sleep.
    readonly wait: Duration = Duration.ofSeconds(10L)
    readonly timeoutMs: int = 30000
}

export class SshCommandResult {
    readonly exitStatus: int
    readonly stdout: string
    readonly stderr: string
}

export class SftpClient {
    private native: NativeSshClient

    // Reads at most maximumBytes; the default keeps an untrusted remote file
    // from consuming unbounded memory.
    isolated readFile(path: string, maximumBytes: long = 16777216L): Result<readonly byte[], string> => native.readSftpFile(path, maximumBytes)
    // Creates or replaces path. Parent directories must already exist.
    isolated writeFile(path: string, data: readonly byte[]): Result<none, string> => native.writeSftpFile(path, data)
    isolated listDirectory(path: string): Result<string[], string> => native.listSftpDirectory(path)
    isolated makeDirectory(path: string): Result<none, string> => native.makeSftpDirectory(path)
    isolated removeFile(path: string): Result<none, string> => native.removeSftpFile(path)
    isolated removeDirectory(path: string): Result<none, string> => native.removeSftpDirectory(path)
    isolated rename(source: string, destination: string, overwrite: bool = false): Result<none, string> => native.renameSftpPath(source, destination, overwrite)
    isolated close(): none => native.closeSftp()
}

import class NativeSshClient from "./native_ssh.hpp" as doof_ssh::NativeSshClient {
    isolated static connect(host: string, port: int, username: string, password: string | none,
        privateKeyPath: string | none, privateKeyPassphrase: string | none,
        knownHostsPath: string | none, hostKeySha256: string | none,
        waitNanos: long, timeoutMs: int): Result<NativeSshClient, string>
    isolated run(command: string, timeoutMs: int): Result<int, string>
    isolated openSftp(): Result<none, string>
    isolated readSftpFile(path: string, maximumBytes: long): Result<readonly byte[], string>
    isolated writeSftpFile(path: string, data: readonly byte[]): Result<none, string>
    isolated listSftpDirectory(path: string): Result<string[], string>
    isolated makeSftpDirectory(path: string): Result<none, string>
    isolated removeSftpFile(path: string): Result<none, string>
    isolated removeSftpDirectory(path: string): Result<none, string>
    isolated renameSftpPath(source: string, destination: string, overwrite: bool): Result<none, string>
    isolated closeSftp(): none
    isolated stdout(): string
    isolated stderr(): string
    isolated close(): none
}

export class SshClient {
    native: NativeSshClient

    // Blocking. This and the native bridge are isolated, so it is suitable for
    // actor-dispatched or async work; it should not run on a UI thread.
    isolated run(command: string, timeoutMs: int = 30000): Result<SshCommandResult, string> {
        status := this.native.run(command, timeoutMs) else error { return { error } }
        return { value: SshCommandResult {
            exitStatus: status,
            stdout: this.native.stdout(),
            stderr: this.native.stderr(),
        } }
    }

    isolated sftp(): Result<SftpClient, string> {
        this.native.openSftp() else error { return { error } }
        return { value: SftpClient { native: this.native } }
    }

    isolated close(): none => this.native.close()
}

export isolated function connect(options: SshConnectOptions): Result<SshClient, string> {
    if options.knownHostsPath == none && options.hostKeySha256 == none {
        return { error: "SSH requires knownHostsPath or hostKeySha256" }
    }
    if options.password == none && options.privateKeyPath == none {
        return { error: "SSH requires password or privateKeyPath" }
    }
    native := NativeSshClient.connect(options.host, options.port, options.username, options.password,
        options.privateKeyPath, options.privateKeyPassphrase, options.knownHostsPath,
        options.hostKeySha256, options.wait.toNanos(), options.timeoutMs) else error { return { error } }
    return { value: SshClient { native } }
}
