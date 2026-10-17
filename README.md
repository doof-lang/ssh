# std/ssh

A blocking, libssh2-backed SSH client. Its native operations are `isolated`, so use it from async or actor work rather than a UI thread.

```doof
import { connect, SshConnectOptions } from "std/ssh"

client := connect(SshConnectOptions {
    host: "server.example",
    username: "deploy",
    privateKeyPath: "/Users/me/.ssh/id_ed25519",
    knownHostsPath: "/Users/me/.ssh/known_hosts",
})!
result := client.run("uptime")!
println(result.stdout)
```

The client requires host-key verification: provide a known-hosts file and/or a SHA-256 host-key fingerprint. For plain OpenSSH entries it prefers algorithms already trusted for the exact host (including `[host]:port` entries), then verifies the complete raw key. Hashed entries remain verified but use the module's modern safe algorithm order because their host name cannot be read before the handshake. A verification failure reports the negotiated algorithm, known-hosts result, and SHA-256 hex fingerprint for diagnosis; verify any replacement key out of band before trusting it.

`connect()` retries an unavailable TCP endpoint for ten seconds by default, which accommodates a VM starting or a machine waking from LAN. Set `wait` to choose a different retry budget (or `Duration.ZERO` for one immediate attempt). It retries only connection availability; handshake, verification, and authentication failures are returned immediately.

```doof
import { Duration } from "std/time"

client := connect(SshConnectOptions {
    host: "server.example",
    username: "deploy",
    privateKeyPath: "/Users/me/.ssh/id_ed25519",
    knownHostsPath: "/Users/me/.ssh/known_hosts",
    wait: Duration.ofSeconds(10L),
})!
```

It supports password or private-key authentication and SFTP. Agent authentication, forwarding, and interactive channels are intentionally future additions.

## SFTP

Open SFTP over the already authenticated, host-verified connection. `writeFile` creates or replaces a file; `readFile` is deliberately bounded (16 MiB by default), so callers must opt in to larger in-memory downloads. Directory operations are non-recursive.

```doof
sftp := client.sftp()!
sftp.writeFile("releases/app.bin", bytes)!
downloaded := sftp.readFile("releases/app.bin")!
names := sftp.listDirectory("releases")!
sftp.rename("releases/app.bin", "releases/app-current.bin")!
sftp.close()
```

An `SshClient` has one shared SFTP session; use it serially, and close the SFTP client before closing the SSH client.
