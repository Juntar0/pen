## make_token
This is a technique where an adversary uses the plaintext credentials of a user to create a new access token, and then impersonates it.

```
make_token CONTOSO\rsteel Passw0rd!
```

This technique does not require a high-integrity context.
## steal_token
This is a technique where an adversary "steals" the primary access token from a process running as a different user.

```
steal_token <PID>
```

This technique _does_ require a high-integrity session.

## token-store
store
```
token-store steal <PID>
```

use
```
token-store use 0
```