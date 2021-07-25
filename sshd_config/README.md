# OpenSSH Hardened Config and Practices

[sshd_config](sshd_config)

This is just a good baseline for general OpenSSH security that, for the most part, can be put on POSIX-compliant systems with OpenBSD's OpenSSH. This does not feature things like access control using `AllowUser`, `DenyUser`, `DenyGroups`, `AllowGroups`, `MatchUser`, `ChrootDirectory`, `PermitOpen`, and `GatewayPorts`; all have very specific and diverse use cases to determine what's necessary for your workspace environment.

### Step Zero: Stop using Dropbear for production.

Dropbear is only meant for low power embedded devices that do not have any real security baseline like routers. It is not as sophisticated and well-maintained as OpenBSD's OpenSSH. Dropbear was simply a university project. These embedded devices should not be connected to a network in the first place with no security baseline.

### Step One: Use an actual up to date distribution.

Distros that package freeze for far too long come with extremely old and outdated versions of OpenSSH dating even as far as 2017. These same distros do not backport important security features, are very lazy and late to backport security patches, and leave in many obsolete and deprecated features that OpenSSH has even completely removed from their source.

This practice is not restricted to OpenSSH. Many distros package freeze their kernels and follow the same bad practice.

Avoid distributions like Manjaro, Debian, Ubuntu (including Server), CentOS (their rolling release version is an exception), Proxmox, and Red Hat Enterprise Linux.

Any other "long term servicing"/LTS distro will usually follow the same bad practices too.

### Step Two: Use SSHFP records

SSHFP records are essentially DANE w/TLSA records but for SSH. Your SSH client will verify the checksum of the host key fingerprint via DNS and make sure it matches the server's host key fingerprint. After first connection, it will then verify those and your locally stored host key fingerprint.

This is to ensure your server's host keys haven't been tampered with and you're not connecting to a malicious server.

You will need to setup A/AAAA DNS records to connect to your server with. Do not use the IP to connect anymore, otherwise you cannot verify SSHFP records.

After applying my hardened sshd config, use the following commands to generate the checksums:

`ssh-keygen -r server.example.com`

The expected output should be some lines of the SSHFP records.

There are two important columns here.
- The first column is the key algorithm.
    - 1 - RSA
    - 2 - DSA
    - 3 - ECDSA
    - 4 - Ed25519
    - 6 - Ed448
- The second column is the fingerprint type.
    - 1 - SHA1
    - 2 - SHA256

You should be using an Ed25519 private key and Ed25519 host key _only_ to connect to your SSH server. DSA is dead. RSA 1024 is dead. RSA 2048 has been broken and is on the road to being cracked. RSA 3072 is at high risk. RSA 4096 is slow and is also at a risk. ECDSA is better than RSA but it still is not as secure and speedy as Ed25519 (I do not imply that ECDSA is insecure at all. It simply is just not on the same level as Ed25519).

Pick only the Ed25519 and SHA256 DNS record as listed and add that to your DNS provider as an `SSHFP` record.

After the TTL, connect to your SSH server with debug1 verbosity (`-v`) and look for the following line to confirm the host key fingerprint was validated by DNS:
```
debug1: matching host key fingerprint found in DNS
```

# [sshd_config](sshd_config) Rationales and Explanations

`Protocol 2`
- Utilize the latest SSH protocol 2. Protocol 1 is obsolete, insecure, and deprecated and is only enabled by specifying it. This is just to be sure we're not falling back to it or supporting both.

`Port 22`
- Using the default port 22 is a little controversial because the general recommended practice is to change the port, usually something above the restricted ports (1024). However, this is poor security by obscurity and only defends you from the generic script kiddie bots that affect every single IPv4 address, not just you. If someone knows your server's IP/domain it is not hard to check all 65,535 ports. Changing your port is not a recommended way to "secure" your server and neither is hiding your server's addresses.
- _"But what if I want to protect from the bots?"_ Stop using passwords, use SSH keys, and use highly secure ciphers. The bots will never be able to get in. Simple as that.

```
ListenAddress 0.0.0.0
ListenAddress ::
```
- Listen on IPv4 and IPv6. If possible, connect via IPv6 as IPv6 has mandatory IPsec. Again, no reason to not listen on IPv4 as it's just security through obscurity.

`HostKey /etc/ssh/ssh_host_ed25519_key`
- Use ONLY the Ed25519 host key. We do not support old and slow keys. This is one part to preventing about 80% of the generic bruteforce bots from being able to attempt a bruteforce.

`RekeyLimit default 1h`
- Renegotiate the SSH session key after a certain amount of data has been transferred, data amount selected by the cipher type, or after a session has persisted for more than one hour. Key rotation helps prevent replay attacks and time-based attacks.
- Note these are public key operations so too frequent key rotation can impact server load. For powerful servers, set the data parameter (default in this case) to about 512M as normal ciphers have a default of 1G-4G. Standard servers leave it default unless replay attacks or time-based are frequent for the clients.

```
Ciphers chacha20-poly1305@openssh.com
HostKeyAlgorithms ssh-ed25519
KexAlgorithms curve25519-sha256
MACs hmac-sha2-512-etm@openssh.com
```
- This is a big security improvement. First, this completely removes the OpenSSL dependency as we are going to be using OpenBSD's implementation of the `chacha20-poly1305` cipher and `hmac-sha2-512-etm` MAC, hence the `@openssh.com` instead of OpenSSL. Knowing OpenSSL not being the best in terms of security due to the bloated API and codebase, this helps tremendously for SSH operations. This applies to SFTP too.
- We also have gotten rid of about 80% of the generic bots as they all use weaker ciphers, MACs, KexAlgo's, and the older host keys instead of Ed25519. The server will reject them. Again, this means you can _only_ use Ed25519 to connect otherwise the server will reject you from attempting to authenticate entirely.
- Example of sshd rejecting most bots:
```
Jul 25 06:35:47 413.zanthed.xyz sshd[31160]: Unable to negotiate with 221.131.165.56 port 46910: no matching host key type found. Their offer: ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss [preauth]
Jul 25 06:44:51 413.zanthed.xyz sshd[33050]: Unable to negotiate with 49.88.112.75 port 25460: no matching host key type found. Their offer: ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss [preauth]
Jul 25 06:46:20 413.zanthed.xyz sshd[33372]: Unable to negotiate with 49.88.112.75 port 33472: no matching host key type found. Their offer: ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss [preauth]
Jul 25 06:54:17 413.zanthed.xyz sshd[35166]: Unable to negotiate with 221.181.185.159 port 64709: no matching host key type found. Their offer: ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss [preauth]
Jul 25 07:06:23 413.zanthed.xyz sshd[37685]: Unable to negotiate with 49.88.112.75 port 19056: no matching host key type found. Their offer: ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss [preauth]
Jul 25 07:18:50 413.zanthed.xyz sshd[40248]: Unable to negotiate with 49.88.112.75 port 31555: no matching host key type found. Their offer: ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss [preauth]
Jul 25 07:22:24 413.zanthed.xyz sshd[41041]: Unable to negotiate with 222.187.232.205 port 62370: no matching host key type found. Their offer: ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss [preauth]
```

This is not foolproof to go back to using insecure authentication like passwords. See:
```
Jul 25 08:20:02 413.zanthed.xyz sshd[52907]: Invalid user postgres from 45.61.185.207 port 56190
Jul 25 08:20:02 413.zanthed.xyz sshd[52904]: Invalid user ubuntu from 45.61.185.207 port 56178
Jul 25 08:20:02 413.zanthed.xyz sshd[52906]: Invalid user vagrant from 45.61.185.207 port 56188
Jul 25 08:20:02 413.zanthed.xyz sshd[52909]: Invalid user oracle from 45.61.185.207 port 56186
Jul 25 08:20:02 413.zanthed.xyz sshd[52908]: Invalid user test from 45.61.185.207 port 56182
Jul 25 08:20:05 413.zanthed.xyz sshd[52907]: Connection closed by invalid user postgres 45.61.185.207 port 56190 [preauth]
Jul 25 08:20:05 413.zanthed.xyz sshd[52904]: Connection closed by invalid user ubuntu 45.61.185.207 port 56178 [preauth]
Jul 25 08:20:06 413.zanthed.xyz sshd[52908]: Connection closed by invalid user test 45.61.185.207 port 56182 [preauth]
Jul 25 08:20:06 413.zanthed.xyz sshd[52909]: Connection closed by invalid user oracle 45.61.185.207 port 56186 [preauth]
Jul 25 08:20:06 413.zanthed.xyz sshd[52906]: Connection closed by invalid user vagrant 45.61.185.207 port 56188 [preauth]
```

- This is the equivalent to using TLS 1.3 only with very modern ciphers only. Since this is a production server, backwards compatibility need not be a concern.

`PermitUserRC no`
- Prevent executing the client's `~/.ssh/rc` file.

```
SyslogFacility AUTHPRIV
LogLevel INFO
```
- Log to syslog about successful and unsuccessful connections. Who did what at when?

`LoginGraceTime 30`
- Give the client thirty seconds to authenticate, otherwise kick them off. This is pretty graceful as initiating a successful connection should not take longer than 10 seconds.

`PermitRootLogin prohibit-password`
- While it is still suggested to disallow this entirely and utilize privilege elevation like `sudo` or `doas` or use secure authentication like Kerberos, given OpenSSH is using a very secure config, it may be totally okay to login as root. Remember, a user with sudo access is the equivalent to root.

`PermitEmptyPasswords no`
- Self explanatory. We're disabling password authentication anyways.

`StrictModes yes`
- Check for world-writable (e.g. `777`) directories and files in the user's home directory before logging in. Prevents a malicious attacker from being able to write and execute files after gaining access to a client's account.

```
MaxAuthTries 5
MaxSessions 5
PubkeyAuthentication yes
```
- Allow 5 attempts before more logging about the account. You can lock the account using PAM and ban the client with a firewall like nftables or firewalld. Do not use fail2ban. Adds a lot of attack surface for being able to do something with a few seconds of googling and commands.
- Allow only a maximum of 5 total logged in sessions. Setting this to zero disallows all shell access and being able to login, but you can still do forwarding. More practical to do on a by-user basis using `MatchUser` such as forwarding-only accounts or FTP accounts.
- Allow key-based authentication. Self explanatory. Authenticate by what you have instead of what you know.

```
HostbasedAuthentication no
IgnoreUserKnownHosts yes
IgnoreRhosts yes
```
- Disallow all forms of host based authentication via `rhosts` or the client's `known_hosts` file.
- Disallow authenticating clients by the system's `rhosts` file. This is deprecated and should not be used anymore.

```
PasswordAuthentication no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
```
- Prevent authenticating by what you know and prevent standard password bruteforce attacks.
- Disallow challenge-response authentication from PAM. We're using SSH keys only. This may be necessary to enable if you use anything like Yubikey OTP for authentication.
- We're not using Kerberos so disable Kerberos authentication and GSSAPI.

```
AllowAgentForwarding no
X11Forwarding no
```
- Disallow agent forwarding. This is not that useful as users can add and implement their own forwarders unless you deny their shell access.
- X11 is insecure, outdated as hell, and needs to be deprecated. A server should not need to install a display server or GUI of any sort. Quit your job if your company relies on X11.

```
PrintMotd no
TCPKeepAlive no
UseDNS yes
Compression no
PermitUserEnvironment no
```
- MOTD is handled by PAM.
- TCPKeepAlive packets can be spoofed. Consider using `ClientAliveCountMax 0` and `ClientAliveInterval 3600` to keep clients alive as these packets are sent through the encrypted tunnel.
- Use remote host name checking to verify the domain matches the same IP address.
- Compression has been found to be vulnerable to similar TLS attacks like CRIME and BREACH when compressing before encryption (`on`). This is a common problem with before encryption compression. If you absolutely need compression, you can get away with `delayed` compression as this is compression after encryption, however the difference is very subtle/not noticeable and was only necessary on very low speed connections like dial-up, or are using X11Forwarding (don't). Nowadays, SSH compression can actually slow the user down. The encryption cipher (ChaCha20-Poly-1305) used is also very light weight.
- Disallow reading `~/.ssh/environment` and the `environment=` options in `~/.ssh/authorized_keys`. This can be used to bypass access restrictions using variables such as `LD_PRELOAD` or `EDITOR`.

`Subsystem sftp /usr/libexec/openssh/sftp-server -u 0077 -l INFO -f AUTHPRIV`
- Use the `sftp-server` binary with a umask `-u 0077`, log to syslog basic info `-l INFO` and authentication attempts `-f AUTHPRIV`.

Finally, avoid allowing variables to be passed through via `AcceptEnv`. As with `PermitUserEnvironment`, allowing variables to be passed through by the client can be used maliciously.

You may be able to run OpenSSH rootless and use less external programs if you get rid of the usage of PAM by setting `UsePAM` to `no`. Do note that this can possibly issues with authentication if you rely on PAM and there will be no MOTD if you handle MOTD by PAM. If you do basic SSH key authentication though, you should be okay. Note that running everything rootless is not always good due to the desktop security model. `UsePrivilegeSeparation` requires root too.

The option `UsePrivilegeSeparation` is deprecated and entirely removed in some cases, but this is not because it's useless. `UsePrivilegeSeparation` has been set to `sandbox` for many years by default and no one has ever had to disable it. Disabling it is impossible without a source code change and this is for a good thing as it uses seccomp, setuid, and setgid to reduce exploitation and prevent privilege escalation by process/memory corruption.

If you need to disable `UsePrivilegeSeparation` such as to make a PAM module work, stop using that PAM module immediately.
