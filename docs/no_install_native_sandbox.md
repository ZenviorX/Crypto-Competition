# 无需安装 Docker 的 Native Sandbox

如果本机没有 Docker Desktop，项目会自动使用 `native_subprocess` 沙箱。

## 定位

`native_subprocess` 不是 Docker、gVisor 或 Firecracker 这种 OS/VM 级隔离。它是一个**项目内置的受限工具解释器沙箱**：

- 不需要安装任何额外软件；
- 使用当前 Python 解释器启动独立子进程；
- 子进程只暴露有限工具：`file.read`、`file.write`、`email.send`、安全解释型 `shell.run`；
- 所有路径必须位于 `runtime_workspace`；
- 根据 `sandbox_profile` 进行路径前缀白名单控制；
- `secret/` 和 `private/` 默认不在允许前缀内；
- 不支持真实网络外发；
- 每次运行生成证据文件。

## 和 Docker 沙箱的区别

| 能力 | Docker Sandbox | Native Sandbox |
|---|---|---|
| 是否需要额外软件 | 需要 Docker Desktop | 不需要 |
| OS 级隔离 | 有 | 没有 |
| 独立文件系统挂载 | 有 | 通过路径白名单模拟 |
| 禁网 | `--network none` | 工具面不提供网络工具 |
| 资源限制 | Docker 参数限制 | 主要依靠超时 |
| 证据文件 | 有 | 有 |
| 适合演示 | 强 | 最稳、无需环境依赖 |

## 执行链路

```text
Tool Proxy allow
      ↓
execute=true + capability_token
      ↓
Hybrid Sandbox Executor
      ↓
Docker 可用？
  ├─ 是：Docker Sandbox
  └─ 否：Native Subprocess Sandbox
      ↓
runtime_workspace/native_sandbox_runs/native_*/evidence.json
```

## 直接测试

```powershell
Invoke-RestMethod http://127.0.0.1:8000/sandbox-native/health

Invoke-RestMethod -Method Post http://127.0.0.1:8000/sandbox-native/execute `
  -ContentType "application/json" `
  -Body '{"tool":"file.read","params":{"path":"public/notice.txt"},"sandbox_profile":"local_readonly"}'
```

测试阻断敏感文件：

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/sandbox-native/execute `
  -ContentType "application/json" `
  -Body '{"tool":"file.read","params":{"path":"secret/password.txt"},"sandbox_profile":"strict"}'
```

预期：返回 `success=false`，原因包含 `outside allowed native sandbox prefixes`。

## 前端演示

进入：

```text
授权工作台 -> Docker 真沙箱执行
```

即使 Docker Desktop 已卸载，后端 Tool Proxy 现在也会自动 fallback 到 `native_subprocess`。前端完整 JSON 里可以看到：

```json
{
  "sandbox_evidence": {
    "sandbox_type": "native_subprocess",
    "requires_external_software": false
  }
}
```

后续可以把前端文案从“Docker 真沙箱执行”统一改为“真沙箱执行（无 Docker 可运行）”。
