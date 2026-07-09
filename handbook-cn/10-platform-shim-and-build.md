# 10 — 平台 Shim 与构建

编排器(Node)很小。两个平台 shim 承担繁重工作:

| Shim                            | 语言 | 包路径                       | 用途                                                                                                   |
| ------------------------------- | -------- | --------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `apply-seccomp-{x64,arm64}`     | C        | `vendor/seccomp/<arch>/`          | Linux seccomp 过滤器安装 + 嵌套 PID 命名空间建立                                                          |
| `srt-win-{x64,arm64}.exe`       | Rust     | `vendor/srt-win/<arch>/`          | Windows:WFP install/verify、沙箱用户配置、双段式启动、ACL 操作、CA-trust 安装                            |

包 `vendor/seccomp-src/` 与 `vendor/srt-win-src/` 是未构建的源码。

## 10.1 `vendor/seccomp-src/apply-seccomp.c`

单个 600 行 C 文件,产出 **静态的、libc 无关** ELF 二进制。

### 构建

```bash
# 在 vendored C 源码目录:
mkdir -p ../seccomp/x64 ../seccomp/arm64
gcc -static -O2 -D__x86_64__ -o ../seccomp/x64/apply-seccomp apply-seccomp.c
aarch64-linux-gnu-gcc -static -O2 -D__aarch64__ -o ../seccomp/arm64/apply-seccomp apply-seccomp.c
```

npm 包的 `vendor/seccomp/build.ts` 在 Linux 上为两个架构编排该流程。macOS/Windows CI 不调用它(它们不打包该二进制)。

### BPF 过滤器源码

`seccomp-unix-block.c` 是 `seccomp` 自身发射的 BPF 程序。编译后的输出 **在构建时被烘焙进** C 二进制:

```c
// 由以下产生: gcc -c -o seccomp-unix-block.o seccomp-unix-block.c
// 然后: objcopy -O binary -j .data seccomp-unix-block.o unix-block-bpf.bin
// 最终: xxd -i unix-block-bpf.bin > unix-block-bpf.h
#include "unix-block-bpf.h"   // ← 包含 `unsigned char unix_block_bpf[] = { ... }`
```

这是正确的 ABI:`unix_block_bpf` 与 libseccomp 产出完全一致的字节序列,但作为 `.rodata` 中的 `const` 数组,因此我们可以直接传给 `prctl(PR_SET_SECCOMP, BPF, &prog)`。无运行时文件 IO。

### 架构相关宏

```c
#if defined(__x86_64__)
#  define SRT_AUDIT_ARCH AUDIT_ARCH_X86_64
#  define SRT_HAS_X32 1
#elif defined(__aarch64__)
#  define SRT_AUDIT_ARCH AUDIT_ARCH_AARCH64
#  define SRT_HAS_X32 0
```

x86_64 支持 x32 ABI(nr 范围 `0x40000000`+),因此 BPF 过滤器在前面有一个额外的跳转以放行任何 x32 系统调用(它们都位于 BPF 必须处理的紧密范围)。aarch64 省略该跳转。

### 为何静态

静态二进制对 glibc/musl 有零运行时依赖。所有发行版上尺寸相同。我们更信任内核 ABI,而非 libc。

## 10.2 `vendor/srt-win-src/`(Rust)

2 万行 Rust 源。Cargo workspace(单一 crate)。

### CLI 子命令

```
srt-win install [--sandbox-user NAME] [--sublayer-guid GUID] [--proxy-port-range lo-hi] [--force]
srt-win uninstall [--sublayer-guid GUID]
srt-win exec -- <command>
srt-win wfp status
srt-win wfp verify
srt-win acl grant --sandbox-user-sid <sid> <path...>
srt-win acl revoke --sandbox-user-sid <sid>
srt-win acl stamp --sandbox-user-sid <sid> <path...>
srt-win acl restore --sandbox-user-sid <sid>
srt-win acl recover
srt-win user status
srt-win user trust-ca <path>
```

当以 argv\[1] = `--srt-win` 启动时(多路模式),分发器路由到相同 handlers。

### 模块

```
src/
├── main.rs           ← CLI 入口;多路分发;信号处理
├── cli.rs            ← 参数解析
├── lib.rs            ← re-exports
├── install.rs        ← `install` / `uninstall` 编排
├── user.rs           ← 本地用户配置 + DPAPI
├── dpapi.rs          ← CryptProtectData / CryptUnprotectData
├── sam.rs            ← 通过 NetAPI 的本地 SAM 操作
├── sid.rs            ← SID 转换辅助
├── wfp.rs            ← WFP 过滤器枚举、添加、删除
├── acl.rs            ← ACL stamp / revoke / restore / recover
├── token.rs          ← Token 限制(CreateRestrictedToken)
├── job.rs            ← Job 对象创建
├── logon.rs          ← CreateProcessWithLogonW 包装
├── launch.rs         ← 双段式编排
├── runner.rs         ← Runner 内部进程:接收 `--password`,exec 子进程
├── state_db.rs       ← SQLite(rusqlite)包装,位于 %LOCALAPPDATA%\sandbox-runtime\state.db
├── cert_store.rs     ← CA 安装/卸载
├── sid.rs            ← SID ↔ 字符串
├── winsta.rs         ← Window-station / desktop 处理
├── self_protect.rs   ← 屏蔽 SDK 篡改
└── path_id.rs        ← 规范路径解析辅助
```

### State DB

```
%LOCALAPPDATA%\sandbox-runtime\state.db
    TABLE sandbox_user
        username        TEXT
        password_dpapi  BLOB     ← CryptProtectData(machine scope)
        marker_version  INT
        sandbox_user_sid TEXT
        sandbox_group_sid TEXT
        created_at_unix  INT
    TABLE user_to_path         ← 按路径对 grant ACE 进行引用计数
        path TEXT
        holder_pid INT
        ACE VARBINARY
    TABLE deny_paths
        path TEXT
        holder_pid INT
        ACE VARBINARY
    TABLE ca_cert
        cert_der BLOB
```

DB 自身有 DACL —— 只有真实用户(和管理员)能打开;沙箱用户被显式 DENY。这是凭证在文件级上的唯一一道闸。

### DPAPI 模块

```rust
pub fn protect_machine(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut blob = CRYPT_INTEGER_BLOB::default();
    CryptProtectData(&CRYPT_DATA_BLOB{ cbData: plaintext.len() as u32, pbData: plaintext.as_ptr() },
                     None, None, None, None,
                     CRYPTPROTECT_LOCAL_MACHINE,
                     &mut blob)?;
    Ok(slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec())
}

pub fn unprotect_machine(blob: &[u8]) -> Result<Vec<u8>> {
    let mut pb = CRYPT_INTEGER_BLOB::default();
    CryptUnprotectData(&CRYPT_DATA_BLOB{ … }, None, None, None, …, &mut pb)?;
    Ok(…)
}
```

解密要求调用进程是 `LocalSystem`、`Administrator`,或 **原始用户**(machine-scope flag 用于 `CryptProtectData`/`CryptUnprotectData`)。Broker 以 broker 权限运行 → 能解密 → 将明文传给 runner → runner 将明文转为受限 token → 子进程拥有该 token 但从未持有密码。

### 双段式启动

```
broker (真实用户,可能非管理员)
    SpawnViaUACelevated(srt-win exec --pw <明文>)
        runner (NT 进程,srt-sandbox 用户)
            ApplyRestrictedToken()
            ApplyJobObject()
            ApplyConsoleWindowStation()   ← 这样子进程可以写控制台
            CreateProcess(...)
                child (srt-sandbox,受限 token)
```

在 token/受限登录设置好之后,runner 立即清零明文密码:

```
<SandboxCred as Drop>:
    for byte in self.pw.bytes_mut() { *byte = 0 }
    self.pw.clear()
```

### WFP 过滤器安装

```rust
fn install() -> Result<()> {
    let engine = FwpmEngineOpen0(None, RPC_C_AUTHN_DEFAULT, None, None, None)?;
    FwpmTransactionBegin0(&engine, 0)?;
    FwpmSubLayerAdd0(&engine, &sublayer)?;
    for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
        FwpmFilterAdd0(&engine, &permit_loopback_filter_for(layer))?;
        FwpmFilterAdd0(&engine, &block_sandbox_user_filter_for(layer))?;
    }
    FwpmTransactionCommit0(&engine)?;
    Ok(())
}
```

过滤器创建使用 `windows` crate 的绑定。每个过滤器的条件:

```rust
fn permit_loopback_conditions(port_range: (u16, u16)) -> Vec<FWPM_FILTER_CONDITION0> {
    vec![
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                value: FWP_CONDITION_VALUE0_0 {
                    v4_addr_and_mask: FWP_V4_ADDR_AND_MASK {
                        addr: 0x7F000000,    // 127.0.0.0
                        mask: 0xFF000000,    // /8
                    }
                }
            }
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                value: FWP_CONDITION_VALUE0_0 {
                    range: FWP_RANGE0 {
                        valueLow: FWP_VALUE0 { uint16: port_range.0, … },
                        valueHigh: FWP_VALUE0 { uint16: port_range.1, … },
                    }
                }
            }
        }
    ]
}
```

阻断条件更简单:

```rust
FWPM_FILTER_CONDITION0 {
    fieldKey: FWPM_CONDITION_ALE_USER_ID,
    matchType: FWP_MATCH_EQUAL,
    conditionValue: FWP_CONDITION_VALUE0 {
        value: FWP_CONDITION_VALUE0_0 {
            sid: sandbox_user_sid,   // FWP_SECURITY_DESCRIPTOR_TYPE
        }
    }
}
```

### ACL 模块

使用 Win32 `SetSecurityInfo()` / `GetSecurityInfo()`。

```rust
pub fn stamp_deny(sid: &str, paths: &[String]) -> Result<()> {
    let trustee = Trustee::from_sid(sid)?;
    for path in paths {
        let sd = get_security_info(path)?;
        let new_deny = explicit_deny_ace(&trustee, MODIFY_ACCESS)?;   // mask
        let new_deny_child = explicit_deny_ace(&trustee, FILE_DELETE_CHILD)?;
        let mut sd' = sd.clone();
        add_explicit_ace(&mut sd', &new_deny)?;
        if let Some(parent) = parent_dir(path) {
            let sd_parent = get_security_info(parent)?;
            let mut parent' = sd_parent.clone();
            add_inherited_ace(&mut parent', &new_deny_child)?;
            set_security_info(parent, &parent')?;
        }
        // 存储原始以供 restore
        db.record_deny(path, current_pid, &sd)?;
        set_security_info(path, &sd')?;
    }
}
```

### CA 安装

```rust
pub fn trust_ca(cert_der: &[u8]) -> Result<()> {
    let creds = read_setup()?.sandbox_creds;     // SandboxCred { user, pw }
    let token = LogonUser(&creds.user, …, &creds.pw, …)?;
    ImpersonateLoggedOnUser(token)?;

    let store = CertOpenStore(CERT_STORE_PROV_REG, …, 0, CERT_SYSTEM_STORE_CURRENT_USER, "Root")?;
    let der = CertCreateCertificateContext(X509_ASN_ENCODING, cert_der)?;
    CertAddCertificateContextToStore(store, der, CERT_STORE_ADD_REPLACE_EXISTING, nullptr)?;

    RevertToSelf()?;
    Ok(())
}
```

token 在每个退出路径被丢弃;注册表写入已完成。

## 10.3 npm 包布局

```
@anthropic-ai/sandbox-runtime/
├── dist/
│   ├── index.js
│   ├── cli.js
│   └── sandbox/*.js + .d.ts.map
├── vendor/
│   ├── seccomp/
│   │   ├── x64/apply-seccomp       ← 由 build:seccomp 在 Linux x64 上填充
│   │   └── arm64/apply-seccomp     ← 由 build:seccomp 在 Linux arm64 上填充
│   └── srt-win/
│       ├── x64/srt-win.exe
│       └── arm64/srt-win.exe
├── README.md
├── LICENSE  (Apache-2.0)
└── package.json
```

`package.json` 中的 `files` 字段:

```json
"files": ["dist", "vendor/seccomp", "vendor/srt-win", "README.md", "LICENSE"]
```

因此注册表安装会携带除源 `.c`/`.rs` 之外的所有内容。

## 10.4 构建流水线

```bash
# Linux (在 CI 中):
gcc -static -O2 apply-seccomp.c -o dist-aux/seccomp-x64/apply-seccomp

# 交叉编译 (CI 为 arm64 执行):
aarch64-linux-gnu-gcc -static -O2 apply-seccomp.c -o dist-aux/seccomp-arm64/apply-seccomp

# Windows (在 CI 中):
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc

# 通用 TypeScript:
tsc           # → dist/
```

`npm run prepare` 运行 `husky`,`npm run prepublishOnly` 运行 `clean && build`。CI 仅在 Linux 架构上在 `test` 之前运行 `build:seccomp`。

## 10.5 多路二进制分发

某些嵌入方希望将 `srt-win` *折叠进* 它们自己的更大二进制(例如安装器)。编排器通过 `SRT_WIN_DISPATCH_ARG1 = '--srt-win'` 支持此行为。当 `windows.srtWin.path` 设置为嵌入方的二进制时,每次调用以前缀 `--srt-win` 作为 argv\[1] 启动,以便嵌入方的分发器可以路由到 `srt_win::run_from_args`。

```
my-embedder.exe ...
my-embedder.exe --srt-win exec -- ...
```

为什么是 argv\[1] 而不是 argv\[0]?Windows 的 `CreateProcessWithLogonW` 与 `ShellExecuteExW(runas)` 不保留伪装的 argv\[0]。argv\[1] 是字面命令行的一部分,被保留。

## 10.6 为何只有两个架构

x86_64 与 aarch64 是受支持的目标。32 位没有严肃的生产部署。**不**支持 i386/armhf,`checkLinuxDependencies` 返回错误而不是静默降级。

seccomp 过滤器因架构而异(不同的 syscall 号、不同的 arg 布局);必须按架构编译。Rust 辅助程序在 syscall 意义上不特定于架构,但因 Rust targets 不同而按架构构建。

## 10.7 编排器从不触碰什么

- 它不直接调用 `NtCreateProcess` —— 那是 runner 的工作。
- 它不写 `HKLM` —— 那是安装器的工作(已提权)。
- 它不调用 `CreateToolhelp32Snapshot` —— 违规监控仅使用 `/proc/<pid>/{cwd,fd/N}`。
- 它不需要 `windows-rs` Win32 头文件 —— 它将包装器作为 Node 模块导入,该模块通过 stdio 将 JSON 代理给 `srt-win` 二进制。编排表面很小(仅 argv)。

这正是 **为何** 这里有 Rust 辅助程序:让编排器的 Win32 表面为零。编排器保持可移植 Node 状态。
