# Docker 真沙箱设计说明

本项目原有的 `sandbox_policy.py` 是策略沙箱：它在工具执行前判断工具、路径、网络、Shell 和副作用是否允许。

本次新增的是执行级 Docker 沙箱：当 Tool Proxy 最终判定为 `allow`，且请求处于 `execute=true` 阶段时，真实工具调用不再直接进入宿主机执行器，而是进入短生命周期 Docker 容器。

## 执行链路

```text
External Agent / Workbench
        ↓
Tool Proxy authorize, execute=false
        ↓
Gateway / OAuth-style Scope / Capability Contract / Runtime Monitor / Sandbox Policy
        ↓
签发 Capability Token
        ↓
Tool Proxy authorize, execute=true + capability_token
        ↓
Docker Sandbox Executor
        ↓
Docker container executes sandbox_tool.py
        ↓
result.json + evidence.json
        ↓
Frontend 展示 Docker 证据
```

## Docker 隔离参数

容器执行使用以下限制：

| 参数 | 作用 |
|---|---|
| `--network none` | 禁止容器联网 |
| `--read-only` | 容器根文件系统只读 |
| `--cap-drop ALL` | 移除 Linux capabilities |
| `--security-opt no-new-privileges` | 禁止提权 |
| `--pids-limit 64` | 限制进程数量 |
| `--memory 128m` | 限制内存 |
| `--cpus 0.5` | 限制 CPU |
| `--tmpfs /tmp:rw,noexec,nosuid,size=16m` | 临时目录不可执行 |
| bind mount readonly | 只挂载允许访问的目录 |

## Profile 映射

| Sandbox Profile | Docker 挂载 | 网络 | 写权限 |
|---|---|---|---|
| `local_readonly` | `public/`、`course/` 只读 | none | 无 |
| `local_safe_write` | `public/`、`course/` 只读，`outbox/` 可写 | none | 仅 outbox |
| `strict` | 仅 `public/` 只读 | none | 无 |
| `no_shell` | 普通文件挂载，但策略层禁止 shell.run | none | 受限 |

`secret/` 和 `private/` 不会挂载进 Docker 容器。即使 Agent 试图访问这些路径，也会先被策略层拒绝；若绕过策略层，容器内也看不到这些目录。

## 证据文件

每次 Docker 执行会生成：

```text
runtime_workspace/sandbox_runs/docker_*/
  input.json
  result.json
  stdout.txt
  stderr.txt
  evidence.json
```

`evidence.json` 包含：

- `run_id`
- `sandbox_type`
- `sandbox_profile`
- `image`
- `docker_available`
- `runtime_policy`
- `mounts`
- `exit_code`
- `tool_result`
- `stdout_tail`
- `stderr_tail`
- `evidence_hash`

## 演示方式

启动项目：

```powershell
python .\start_project.py --clean
```

打开前端：

```text
http://localhost:5173
```

进入：

```text
授权工作台 -> Docker 真沙箱执行
```

推荐样例：

```text
Docker 沙箱读取 public/notice.txt
Docker 沙箱写入 outbox/docker_demo.txt
Docker 沙箱尝试读取 secret/password.txt 敏感文件
```

也可以直接调用后端：

```powershell
Invoke-RestMethod http://127.0.0.1:8000/sandbox-docker/health

Invoke-RestMethod -Method Post http://127.0.0.1:8000/sandbox-docker/execute `
  -ContentType "application/json" `
  -Body '{"tool":"file.read","params":{"path":"public/notice.txt"},"sandbox_profile":"local_readonly"}'
```

## 注意

本功能需要本机安装并启动 Docker Desktop。若 Docker 不可用，后端会返回 `docker_available=false`，前端会展示失败原因，但不会影响原有策略沙箱和测试模块。
