# 🧬 ELU

*A tiny embeddable policy language — like JSON5 grew up and got a job in security.*

<!--START_SECTION:repo_stats-->
⭐ **Stars** 

```text
Total: 1
```

🍴 **Forks** 

```text
Total: 0
```

📋 **Issues** 

```text
Open: 0
```

🔀 **Pull Requests** 

```text
Open: 0
```

💬 **Languages** 

```text
Go                       100.0%              █████████████████████████   100.00 % 
```

👥 **Top Contributors** 

```text
github-actions[bot]      8 commits           █████████████░░░░░░░░░░░░   53.33 % 
eluuna461                5 commits           ████████░░░░░░░░░░░░░░░░░   33.33 % 
narukoshin               2 commits           ███░░░░░░░░░░░░░░░░░░░░░░   13.33 % 
```

🕐 **Recent Commits** 

```text
readme-bot: Updated with commit 1            ██░░░░░░░░░░░░░░░░░░░░░░░   10.00 % 
readme-bot: Updated with commit 2            ██░░░░░░░░░░░░░░░░░░░░░░░   10.00 % 
readme-bot: Updated with commit 3            ██░░░░░░░░░░░░░░░░░░░░░░░   10.00 % 
AIRI: fix: allow-list .ascommit 4            ██░░░░░░░░░░░░░░░░░░░░░░░   10.00 % 
readme-bot: Updated with commit 5            ██░░░░░░░░░░░░░░░░░░░░░░░   10.00 % 
```

![Stats chart](https://raw.githubusercontent.com/THERXWOLD/ELU/main/.assets/repo_stats.svg)

![Languages chart](https://raw.githubusercontent.com/THERXWOLD/ELU/main/.assets/repo_languages.svg)

![Contributors chart](https://raw.githubusercontent.com/THERXWOLD/ELU/main/.assets/repo_contributors.svg)

![Commits chart](https://raw.githubusercontent.com/THERXWOLD/ELU/main/.assets/repo_commits.svg)


<!--END_SECTION:repo_stats-->

<img src="https://img.shields.io/badge/go-1.22+-00ADD8?logo=go&logoColor=white"> <img src="https://img.shields.io/badge/status-experimental-orange"> <img src="https://img.shields.io/badge/license-GPLv3-blue"> <img src="https://img.shields.io/badge/PRs-welcome-brightgreen">

> [!WARNING]
> Early days. ELU works, tests pass, used in production-adjacent things — but the API isn't frozen yet. Expect bumps.

ELU started as the policy layer for Eluuna — a private AI project — and grew into something generic enough to share. It's mainly for internal use, but we don't mind putting it out there in case it's useful to others. Also because it pisses Naru off to edit hardcoded permissions in the backend and restart the service every time a new capability needs access control. YAML/JSON policy files get painful fast when you need conditions, validation, and composition without reaching for a full programming language. ELU is the middle ground: structured enough to parse, expressive enough to be useful, small enough to embed.

---

📚 **Contents**
- [Why not YAML/JSON](#why-not-yamljson)
- [Quick start](#quick-start)
- [Pack types](#pack-types)
- [Examples](#examples)
- [CLI](#cli)
- [Library usage](#library-usage)
- [Package layout](#package-layout)
- [Hardening notes](#hardening-notes)
- [Contributing](#contributing)
- [License](#license)

---

# 🤔 Why not YAML/JSON

You *can* write policies in YAML. You'll end up writing a custom validator, a condition evaluator, and a merge strategy anyway. ELU gives you all of that out of the box:

- First-class conditions (`when: - resource.owner_id eq $subject.id`)
- Fail-closed semantics (`never > deny > approval > propose > allow`)
- Built-in validation for 6 pack types
- Extension registry for custom operators and pack validators
- Canonical formatter so you never argue about indentation again
- Diagnostic errors with file:line:col — no more "invalid config at line 42" with no context

---

# ⚡ Quick start

```sh
git clone https://github.com/THERXWOLD/ELU
cd ELU

go test ./...
```

---

# 📦 Pack types

| Type | Purpose |
|------|---------|
| `access_policy` | Role-based access control with conditions & precedence |
| `route_policy` | HTTP route rules — roles, MFA, audit, conditions |
| `repo_policy` | Repository permissions with glob matching |
| `skill_pack` | Agent skill manifests |
| `guardrail_pack` | Hard safety gates & approval rules |
| `filter_pack` | Detection / redaction / blocking filters |

---

# 🔬 Examples

**Access policy** — who can do what, and under what conditions:

This policy controls access to a website's resources. It defaults to deny (everyone starts locked out), then opens specific permissions for each role. The `author` role can edit their own blog drafts, but only while the post is still in draft status — the `when` block makes sure `resource.owner_id` matches the requester's identity and the post hasn't been published yet. This prevents authors from editing published content without going through approval.

```elu
pack "app.security.access" version 1
type = "access_policy"

access "website":
  default = "deny"

  role "author":
    rule "edit_own_draft":
      effect = "allow"
      action = "update"
      resource = "blog.post"

      when:
        - resource.owner_id eq $subject.id
        - resource.status eq "draft"
```

The `when` block desugars into safe structured conditions — `owner_id eq $subject.id` is a condition operator, not a string you'll need to parse yourself. Unknown operators fail validation. Runtime errors fail closed to `never`. Every rule has an explicit `effect`, so there's no guessing whether something was accidentally allowed.

**Guardrail pack** — hard safety rules that an AI must follow, no exceptions:

This policy defines hard guardrails for an AI assistant. It blocks any action that could expose secrets — reading a file, writing to memory, sending output — if the content matches a secret pattern. Rather than auditing after the fact, it evaluates before the tool runs and blocks the entire operation if triggered. The `applies_to` list says which tools are in scope, and `never` lists the specific behaviors that are forbidden regardless of context.

```elu
pack "eluuna.guardrails.core" version 1
type = "guardrail_pack"

priority = "critical"

guardrail "no_secret_exposure":
  severity = "critical"
  applies_to:
    - "repo.read"
    - "file.read"
    - "memory.write"
    - "output.send"
  never:
    - "print secrets"
    - "copy secrets into prompts"
    - "send secrets to external models"
  on_violation:
    action = "block"
    report = "Secret exposure attempt blocked."
```

Guardrails are evaluated at runtime before any action is taken. If a guardrail triggers, the action is blocked before it reaches the tool — no `defer`-and-hope pattern, no after-the-fact logging. Fail-closed by default, because safety shouldn't be best-effort.

---

# 🖥 CLI

```sh
# Validate with production rules
go run ./cmd/elu check --production ./examples/access_policy/website.elu

# Check formatting
go run ./cmd/elu fmt --check ./examples/access_policy/website.elu

# Dump AST
go run ./cmd/elu ast ./examples/access_policy/website.elu

# Evaluate a policy decision
go run ./cmd/elu explain ./examples/access_policy/website.elu \
  --role admin --action read --resource blog.post
```

---

# 📖 Library usage

```go
import "github.com/therxwold/elu"

f, err := elu.ParseFile("policy.elu")
// handle error

reg := elu.NewRegistry()
diags := elu.ValidateFile(f, reg, true)
if diags.HasErrors() {
    // report diagnostics
}

dec, err := elu.DecodeAccessPolicy(f)
// use the decoded policy
```

---

# 🗂 Package layout

```
access/      access_policy decoder/evaluator
route/       route_policy decoder/evaluator
repo/        repo_policy decoder/evaluator
skill/       skill_pack decoder/validator
guardrail/   guardrail_pack decoder/validator
filter/      filter_pack decoder/validator
condition/   structured condition parser/evaluator
parser/      .elu parser
ast/         AST types
extension/   custom operator/pack registry
format/      canonical formatter
validate/    validation entrypoint
value/       runtime value type
diag/        diagnostic types
policy/      shared Effect type
e2e/         end-to-end policy tests
cmd/elu/     CLI
examples/    sample .elu files
docs/        design and usage docs
vscode/      VS Code syntax highlighting extension
```

---

# 🛡 Hardening notes

> [!CAUTION]
> Fail-closed by default. When in doubt, deny. That's the ELU way.

- Unknown or malformed conditions fail validation when possible
- Runtime condition errors fail closed to `never`
- `never > deny > approval > propose > allow`
- Access, repo, and route share the same `policy.Effect` type
- Custom pack types require a registered validator in strict mode
- Condition shorthand desugars into safe structured conditions
- Condition nodes cannot mix logical-group shape with leaf field/op/value shape
- Protected route entries require `require_role` — `when:` or `require_2fa` alone doesn't count as auth
- Filter action maps must match their detector type

---

# 🤝 Contributing

PRs welcome. Open an issue first if it's a big change — we're nice, we promise. Please include test cases.

---

# 📜 License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

---

> [!NOTE]
> **Credits:** Naru K (design) · AIRI/Eluuna (implementation) · ChatGPT-chan (debugging & rabbit-hole rescue)

*Built with ❤️ and too much caffeine at therXwold.dev*
