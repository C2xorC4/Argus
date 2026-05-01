# Lab-target SSH setup

How to wire a Proxmox / Hyper-V / bare-metal Linux research VM
into Argus so that dev tooling and Claude Code sessions can run
commands on it via SSH.

The pattern is also reusable for any other test target — just
change the alias and the inventory under
`config/argus.local.toml:[lab_target]`.

## Operational model

1. The VM has a dedicated Argus user (`argus`) with NOPASSWD sudo.
   Blast radius is bounded to the VM (it's research lab, not
   production).
2. The Windows host has an SSH key (`~/.ssh/argus_lab`) and a
   matching Host entry in `~/.ssh/config` aliased `argus-lab`.
3. Argus's dev tools read `[lab_target].ssh_alias` from
   `config/argus.local.toml` and `ssh argus-lab "command"` against
   it.
4. Destructive operations (`rmmod`, `modprobe`, `mkfs`, `dd`,
   `reboot`, etc.) gate on operator confirmation — the lab is
   throwaway but accidental loss of in-flight test state is still
   annoying.

## Setup checklist

### On the VM (one-time)

```bash
# 1. Create the dedicated user
sudo useradd -m -s /bin/bash -G sudo argus
sudo passwd argus       # set a strong password (used once for ssh-copy-id)

# 2. Configure NOPASSWD sudo
echo "argus ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/argus-nopasswd
sudo chmod 440 /etc/sudoers.d/argus-nopasswd

# 3. Install standard tooling so I don't need to bootstrap each session
sudo apt update && sudo apt install -y \
    build-essential gcc g++ make cmake \
    git curl wget rsync \
    python3-pip python3-venv \
    linux-headers-$(uname -r) \
    gdb strace ltrace \
    bpftrace bpfcc-tools \
    linux-tools-common linux-tools-$(uname -r)
```

For the CVE-2026-31431 work specifically, you'll also want the
affected kernel installed:

```bash
# Ubuntu 24.04 — affected kernel
sudo apt install -y linux-image-6.17.0-1007-aws \
                    linux-modules-6.17.0-1007-aws \
                    linux-modules-extra-6.17.0-1007-aws
sudo update-grub
sudo reboot
# Verify after reboot:
uname -r        # should print 6.17.0-1007-aws
```

### On the Windows host (one-time per host)

> **Shell matters on Windows.** PowerShell and git-bash expand `~`
> to `%USERPROFILE%`; **cmd.exe does not** — there `~` is a literal
> character and `ssh-keygen -f ~/.ssh/argus_lab` fails with
> "No such file or directory." Use the absolute path form
> (`%USERPROFILE%\.ssh\argus_lab`) from cmd, or switch to
> PowerShell / git-bash for the tilde form.

```powershell
# PowerShell (or git-bash)
mkdir -Force "$env:USERPROFILE\.ssh"

# 1. Generate a dedicated key for this lab
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\argus_lab" -C "argus-research-lab"

# 2. Copy the public key to the VM (asks for the VM password you set above)
ssh-copy-id -i "$env:USERPROFILE\.ssh\argus_lab.pub" argus@<vm-ip>

# 3. Add a Host entry in ~/.ssh/config
#    Append the block below to: %USERPROFILE%\.ssh\config

Host argus-lab
    HostName <vm-ip>
    User argus
    IdentityFile ~/.ssh/argus_lab
    IdentitiesOnly yes
    ServerAliveInterval 60
    StrictHostKeyChecking accept-new
EOF

# 4. Verify
ssh argus-lab "id; sudo -n true && echo 'sudo OK'"
# Expected output:
#   uid=1001(argus) gid=1001(argus) groups=1001(argus),27(sudo)
#   sudo OK
```

### In Argus

Add the target to your local config:

```toml
# config/argus.local.toml
[lab_target]
ssh_alias       = "argus-lab"
description     = "Proxmox Ubuntu 24.04 + linux-image-6.17.0-1007-aws"
default_workdir = "~/argus"
```

Test the wiring:

```bash
bash dev/lab_run.sh "uname -a; lsmod | grep -E 'algif|authencesn' || echo 'modules not currently loaded (expected)'"
```

## What I'll do via this channel

Typical operations:

- **Pull the affected kernel modules:**
  ```bash
  bash dev/lab_run.sh "cp /lib/modules/\$(uname -r)/kernel/crypto/algif_aead.ko \$HOME/algif_aead.ko && cp /lib/modules/\$(uname -r)/kernel/crypto/authencesn.ko \$HOME/authencesn.ko && ls -la \$HOME/*.ko"
  scp argus-lab:~/algif_aead.ko argus-lab:~/authencesn.ko \
      vulntest/known-positive/CVE-2026-31431/binary/
  ```
- **Run analysis remotely** — same Argus install on Linux side via
  WSL or by scp'ing the analysis output back.
- **Trigger PoC under instrumentation** (Phase 4 work) — capture
  KASAN logs, dmesg, sanitizer output.
- **Compile** — KASAN-instrumented kernels, custom test harnesses,
  fuzzers.

Destructive commands gate on operator confirmation by default.

## Multiple targets

Add more `Host` entries in `~/.ssh/config` and configure multiple
targets in `config/argus.local.toml` by adding additional `[lab_target.<name>]`
sections in a future iteration if the workflow needs them. For
Phase 1 / 2, single target is sufficient.

## Security notes

- The SSH key is dedicated to the lab; **don't reuse your normal
  development key**. If the VM ever gets compromised, the
  exposure is bounded.
- NOPASSWD sudo is acceptable here because the VM is throwaway
  and isolated. **Don't apply this pattern to production hosts.**
- The VM should be on an isolated VLAN or a Proxmox-NAT'd network
  if you're running PoCs that include network components. The
  CVE-2026-31431 PoC is local-process-only, so plain bridge
  networking is fine.

## Resumption pointer

Once SSH wiring lands, Phase 4 verification work picks up
naturally:

- `scripts/verify/sanitizer.py` — runs PoC under sanitizer, ingests
  KASAN-instrumented kernel oops output, transitions Finding to
  IMPACT_VERIFIED.
- `scripts/verify/debugger.py` — drives a remote gdb / drgn
  session over SSH for step-through verification.

Phase 4 isn't built yet; the SSH plumbing is its prerequisite.
