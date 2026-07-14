# Support

Thanks for using SecuroGuard. Here is how to get help.

## Before opening an issue

- Read the [README](README.md) — especially "How it works", "Baseline setup", and
  "Limitations & threat model".
- Check the [docs](docs/) for the architecture, threat model, and advisory format.
- **"Unknown" does not mean "malicious."** SecuroGuard reports unknown files as
  informational, not as threats.

## Questions and usage help

- Open a [GitHub Discussion](https://github.com/JohnCDupe/SecuroGuard/discussions)
  for questions, or use the **Feature request** issue template for a concrete proposal.
- Please include: your Minecraft/Fabric/Java versions, whether you are using the
  Fabric mod or the Sentinel, the exact command or action, and the relevant output.

## Bug reports

- Use the **Bug report** issue template.
- Do **not** attach live malware, access tokens, `launcher_accounts.json`,
  credential files, or private world/user files. Share hashes and redacted output
  instead. The Sentinel's `--redact` flag helps produce shareable output.

## Security vulnerabilities

Please do **not** open a public issue for a suspected vulnerability. Follow the
private process in [SECURITY.md](SECURITY.md).

## What is out of scope

SecuroGuard is a Minecraft integrity monitor, not a general antivirus. It cannot
scan your whole computer, and it cannot reliably contain code that is already running
inside the Minecraft JVM. The external Sentinel is the stronger, pre-launch boundary.
