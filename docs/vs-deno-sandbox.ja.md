# BotBox vs Deno Sandbox（allowNet + secrets）

このドキュメントは、Deno Sandbox のアウトバウンド制御（`allowNet`）と資格情報の注入（`secrets`）を、BotBox の仕組みと比較します。Deno 側は `@deno/sandbox` SDK ドキュメント（JSR）に基づきます。

狙いは、自律型エージェントの封じ込め（containment）に関して次を評価することです:

- 任意の宛先への流出（exfiltration）をどこまで減らせるか
- 資格情報の *値* をエージェントコードから隠せるか
- 許可済み上流（allowlist 済みホスト）を経由した悪用/流出が何として残るか

> このドキュメントは `docs/vs-deno-sandbox.md` の日本語版です。内容に差異がある場合は英語版が正です。

## 問題設定

エージェント的なコーディングでは、次を同時に満たす必要が出がちです:

- GitHub API のようなセンシティブな上流 API に到達できること
- API キー/トークン等の資格情報で認証できること

ホスト allowlist は到達可能な宛先集合を減らせますが、allowlist 済み上流を経由した悪用/流出は止められません。

本ドキュメントでは、少なくとも次の 2 つを分離して考えます:

1. secret value exfiltration: エージェントが資格情報の値を知り、その値を漏らす。
2. token misuse / data exfiltration: 値を知らなくても、注入された資格情報を使って不正操作やデータ流出を行う。

## 一次情報（引用）

Deno Sandbox（`@deno/sandbox`）:

> "Create isolated sandboxes on Deno Deploy to securely run code in a lightweight Linux microVM." ([DENO-OVERVIEW])

> "You can restrict which hosts the sandbox can make outbound network requests to using the `allowNet` option." ([DENO-ALLOWNET])

> "If `allowNet` is not specified, no network restrictions are applied." ([DENO-ALLOWNET])

> Supported patterns:
> - Exact hostnames with optional ports: "example.com", "example.com:80"
> - Wildcard subdomains with optional ports: "*.example.com", "*.example.com:443"
> - IP addresses with optional ports: "203.0.113.110", "203.0.113.110:80"
> - IPv6 addresses with optional ports: "[2001:db8::1]", "[2001:db8::1]:443" ([DENO-ALLOWNET])

> "Set secret environment variables that are never exposed to sandbox code. The real secret values are injected on the wire when the sandbox makes HTTPS requests to the specified hosts." ([DENO-SECRETS])

BotBox（このリポジトリ）:

> "BotBox is a Kubernetes sidecar proxy that sits between your container and the internet. It intercepts all outbound traffic via iptables, enforces a deny-by-default allowlist, and injects API keys at the network boundary — so the container itself never holds credentials and can only reach hosts you explicitly permit." ([BOTBOX-README-OVERVIEW])

> "- **The agent never sees real API keys.** Credentials are stored in Kubernetes Secrets and injected by BotBox at the network layer." ([BOTBOX-README-CONTAINMENT])

> "- **Auditable.** Every request is logged with structured tracing. You can see exactly what your agent tried to reach and whether it was allowed or denied." ([BOTBOX-README-CONTAINMENT])

> "- Policy is host-based with exact match semantics." ([BOTBOX-SECURITY-EGRESS])

> "- Policy is port-aware: requests default to port 443 only unless `allowed_ports` is explicitly configured per rule." ([BOTBOX-SECURITY-EGRESS])

> "- Deployments must prevent direct outbound connections from application containers (iptables OUTPUT filter rules and/or NetworkPolicy). NAT redirect alone is bypassable for HTTPS and QUIC." ([BOTBOX-SECURITY-EGRESS])

> "| Filter: `-p udp -j DROP` | Block all other direct outbound UDP from app containers (prevents QUIC bypass) |" ([BOTBOX-ARCH-IPTABLES])

> "- `CONNECT` is explicitly rejected (`405`) to prevent generic TCP tunnel behavior." ([BOTBOX-SECURITY-HARDENING])

> "- Rewrites use delete-then-add behavior to remove all prior values first." ([BOTBOX-SECURITY-REWRITE])

> "- Secret-backed values are resolved via `secret_ref` and injected via templates." ([BOTBOX-SECURITY-REWRITE])

> "- Missing secrets fail closed for that request (`500`) instead of forwarding without credentials." ([BOTBOX-SECURITY-REWRITE])

> "When HTTPS interception is enabled, BotBox terminates and re-originates TLS for outbound HTTPS traffic." ([BOTBOX-SECURITY-HTTPS])

> "- The CA private key (`ca_key_path`) must **never** be mounted into app containers." ([BOTBOX-SECURITY-HTTPS])

> "Absolute-form requests (`GET http://host/path`) are rejected because the URI authority could override the Host header and bypass security checks." ([BOTBOX-SECURITY-HTTPS])

> "- Policy is hostname-based; DNS trust remains part of the security boundary." ([BOTBOX-SECURITY-RESIDUAL])

> "- BotBox does not inspect payload content for exfiltration." ([BOTBOX-SECURITY-RESIDUAL])

> "- **IPv6 bypass:** ... When `BOTBOX_ENABLE_IPV6=0`, IPv6 traffic bypasses the proxy entirely ..." ([BOTBOX-SECURITY-RESIDUAL])

## 境界（Boundary）と前提（Trust Model）

### 分離境界

Deno Sandbox は「軽量 Linux microVM」として説明されています（[DENO-OVERVIEW]）。BotBox は Kubernetes のサイドカー型プロキシとして説明されています（[BOTBOX-README-OVERVIEW]）。

実務上の含意:

- Deno Sandbox は VM 境界で実行を分離する前提。
- BotBox は compute/filesystem sandbox を目標にせず、ネットワーク境界における egress 制御と資格情報の取り扱いにフォーカス。

### 何を封じ込めるのか

どちらも主目的は「アウトバウンド通信」と「資格情報露出」の制御です:

- Deno Sandbox: `allowNet` による制限と、`secrets` による on-the-wire 注入（[DENO-ALLOWNET], [DENO-SECRETS]）。
- BotBox: iptables + allowlist + 境界注入。加えてアプリコンテナからの直接アウトバウンドを塞ぐ必要が明記されています（[BOTBOX-SECURITY-EGRESS]）。

## egress ポリシー: セマンティクスと表現力

### ホストマッチ

- Deno `allowNet` はワイルドカード、IP、IPv6 リテラル（任意ポート付き）を含むパターンをサポートします（[DENO-ALLOWNET]）。
- BotBox は exact match のホスト allowlist として記述されています（[BOTBOX-SECURITY-EGRESS]）。

トレードオフ:

- ワイルドカードは設定コストを下げますが、許可範囲が意図せず広がる可能性があります。
- exact match は曖昧さを減らしますが、必要なホストを列挙する必要があります。

### 未設定時のデフォルト

`@deno/sandbox` のドキュメントでは、`allowNet` 未指定の場合にネットワーク制限が適用されないと明記されています（[DENO-ALLOWNET]）。BotBox は deny-by-default allowlist と境界注入を前提に説明されています（[BOTBOX-README-OVERVIEW], [BOTBOX-SECURITY-EGRESS]）。

### ポートの扱い

- Deno `allowNet` は任意ポート付きのパターンをサポートします（[DENO-ALLOWNET]）。
- BotBox はデフォルトで 443 のみ許可し、非 443 は `allowed_ports` で明示する、と記述されています（[BOTBOX-SECURITY-EGRESS]）。

## secret 注入: どこに secret を置き、どう適用するか

### Deno Sandbox `secrets`

ドキュメント上、`secrets` は sandbox code に公開されず（"never exposed to sandbox code"）、指定ホストへの HTTPS リクエスト時に on-the-wire で注入される、と説明されています（[DENO-SECRETS]）。

引用した範囲の記述だけでは、sandbox 内での見え方（未設定なのかプレースホルダなのか）や具体的な実装方式は規定されていません。契約としては "never exposed" と "injected on the wire" が明示されています（[DENO-SECRETS]）。

### BotBox 境界注入

BotBox は「コンテナ自体が資格情報を保持しない」こと、およびネットワーク境界で API キーを注入することが記述されています（[BOTBOX-README-OVERVIEW]）。secret は `secret_ref` を介して解決され、テンプレートで注入され、delete-then-add と fail closed が記述されています（[BOTBOX-SECURITY-REWRITE]）。

## 強制点（Enforcement Point）とバイパス面（BotBox）

BotBox は NAT redirect のみでは不十分であり、アプリコンテナからの直接アウトバウンドを塞がないと HTTPS/QUIC でバイパス可能である、と明記しています（[BOTBOX-SECURITY-EGRESS]）。

参照されている iptables 設計には、QUIC バイパスを防ぐための UDP DROP が含まれます（[BOTBOX-ARCH-IPTABLES]）。

また、汎用トンネル化を避けるため CONNECT を拒否することが記述されています（[BOTBOX-SECURITY-HARDENING]）。

HTTPS interception 有効時は TLS を終端して再接続し、absolute-form を拒否するなどの追加制約でバイパスを減らすことが説明されています（[BOTBOX-SECURITY-HTTPS]）。

## 「許可済み上流」ケース（例: GitHub）

### 1) secret value exfiltration

どちらも、ドキュメント上は「エージェントが資格情報の値を知れない」ことを狙っています:

- Deno: "never exposed" + on-the-wire 注入（[DENO-SECRETS]）。
- BotBox: "container itself never holds credentials" + secret-backed rewrite の fail closed（[BOTBOX-README-OVERVIEW], [BOTBOX-SECURITY-REWRITE]）。

正しく適用されていれば「値を表示して漏らす」という単純な漏洩を抑止できます。

### 2) token misuse / allowlist 済み上流への流出

一方で、どちらも単体では、注入された資格情報を使って allowlist 済み上流に対して有害な操作やデータ流出を行うこと自体は防げません（値の開示がなくても成立します）。

対策は egress 境界の外側が中心です:

- 最小権限・fine-grained・短命なトークン
- 上流側ガード（repo protection、required review、scope 制限等）
- allowlist の最小化

## Attack/Defense Matrix（エージェント脅威）

凡例:

- Mitigated: ドキュメント上、設計として防ぐことが明示されている。
- Not mitigated: モデル上可能、または保証の範囲外。
- Unknown: 引用した一次情報からは不明。

| 脅威 | Deno Sandbox（`allowNet` / `secrets`） | BotBox |
|---|---|---|
| 値の漏洩（env を出力・ファイルを読む等） | "never exposed" により Mitigated（[DENO-SECRETS]） | "never holds credentials" + 境界注入で Mitigated（[BOTBOX-README-OVERVIEW], [BOTBOX-SECURITY-REWRITE]） |
| 任意ドメインへの流出（HTTPS） | `allowNet` に含めなければ Mitigated（[DENO-ALLOWNET]） | deny-by-default allowlist かつ直接アウトバウンド遮断が前提（[BOTBOX-README-OVERVIEW], [BOTBOX-SECURITY-EGRESS]） |
| allowlist 済み上流への流出 | allowlist と value-hiding だけでは Not mitigated | allowlist と value-hiding だけでは Not mitigated |
| 注入トークンによる不正操作 | value-hiding だけでは Not mitigated | value-hiding だけでは Not mitigated |
| QUIC バイパス | 一次情報から Unknown | UDP 遮断が適用されていれば Mitigated（[BOTBOX-SECURITY-EGRESS], [BOTBOX-ARCH-IPTABLES]） |
| IPv6 バイパス | 一次情報から Unknown（ただし allowNet は IPv6 パターンをサポート）（[DENO-ALLOWNET]） | IPv6 無効時のバイパスが明記（[BOTBOX-SECURITY-RESIDUAL]） |

## 残存リスク（BotBox）

BotBox は封じ込めに関係する制約を明記しています:

- ホスト名ベースであり DNS trust が境界の一部（[BOTBOX-SECURITY-RESIDUAL]）。
- ペイロード内容を検査しない（[BOTBOX-SECURITY-RESIDUAL]）。
- IPv6 無効時はバイパス（[BOTBOX-SECURITY-RESIDUAL]）。
- HTTPS interception は CA key compromise とメモリ内平文露出のリスク（[BOTBOX-SECURITY-HTTPS], [BOTBOX-SECURITY-RESIDUAL]）。

## 実務上の推奨（許可済み上流）

強力な上流を allowlist し、資格情報をその上流で使えるようにする以上、主要な安全レバーは「資格情報の最小化」です:

- 最小権限・fine-grained・短命なトークン
- allowlist の最小化
- 上流側ガード（repo protection、required review、厳格な scope）

BotBox 固有の運用ポイントは、一次情報にある要件から導かれます:

- アプリコンテナからの直接アウトバウンドを遮断（OUTPUT filter / NetworkPolicy）（[BOTBOX-SECURITY-EGRESS]）。
- owner-match 前提を崩さない（BotBox UID でアプリを動かさない）（[BOTBOX-ARCH-UID]）。
- HTTPS interception を使うなら CA private key を BotBox のみにマウント（[BOTBOX-SECURITY-HTTPS]）。

## 結論

Deno Sandbox `secrets` と BotBox の境界注入は、どちらも資格情報の *値* をエージェントコードから見えなくすることを狙っています（[DENO-SECRETS], [BOTBOX-README-OVERVIEW]）。これは、センシティブな上流を allowlist せざるを得ない場合でも「値そのものの漏洩」を抑止する、allowlist-only 設計の弱点を補う方向です。

ただし、allowlist 済み上流への token misuse / データ流出は単体では止められません。残るリスクは最小権限化、上流側のガード、allowlist の最小化で管理する必要があります。

## References

- [DENO-OVERVIEW] https://jsr.io/@deno/sandbox#@deno/sandbox
- [DENO-ALLOWNET] https://jsr.io/@deno/sandbox#restrict-outbound-network-access
- [DENO-SECRETS] https://jsr.io/@deno/sandbox#secret-on-the-wire
- [BOTBOX-README-OVERVIEW] https://github.com/reoring/botbox/blob/main/README.md#L13-L15
- [BOTBOX-README-CONTAINMENT] https://github.com/reoring/botbox/blob/main/README.md#L19-L24
- [BOTBOX-SECURITY-EGRESS] https://github.com/reoring/botbox/blob/main/docs/security.md#L41-L53
- [BOTBOX-SECURITY-HARDENING] https://github.com/reoring/botbox/blob/main/docs/security.md#L57-L66
- [BOTBOX-SECURITY-REWRITE] https://github.com/reoring/botbox/blob/main/docs/security.md#L71-L78
- [BOTBOX-SECURITY-HTTPS] https://github.com/reoring/botbox/blob/main/docs/security.md#L99-L140
- [BOTBOX-SECURITY-RESIDUAL] https://github.com/reoring/botbox/blob/main/docs/security.md#L185-L194
- [BOTBOX-ARCH-IPTABLES] https://github.com/reoring/botbox/blob/main/docs/architecture.md#L141-L154
- [BOTBOX-ARCH-UID] https://github.com/reoring/botbox/blob/main/docs/architecture.md#L156-L158
