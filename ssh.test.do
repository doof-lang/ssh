import { Assert } from "std/assert"
import { Duration } from "std/time"
import { connect, SshConnectOptions } from "./index"

function isFailure<T, E>(result: Result<T, E>): bool {
    return case result {
        _: Success -> false,
        _: Failure -> true,
    }
}

export function testConnectRequiresHostVerification(): none {
    Assert.isTrue(isFailure(connect(SshConnectOptions {
        host: "example.com",
        username: "user",
        password: "password",
    })))
}

export function testConnectRequiresAuthentication(): none {
    Assert.isTrue(isFailure(connect(SshConnectOptions {
        host: "example.com",
        username: "user",
        hostKeySha256: "0000000000000000000000000000000000000000000000000000000000000000",
    })))
}

export function testConnectWaitDefaultsToFiveSeconds(): none {
    options := SshConnectOptions {
        host: "example.com",
        username: "user",
    }
    Assert.equal(options.wait.toNanos(), Duration.ofSeconds(5L).toNanos())
}
