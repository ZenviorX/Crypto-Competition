# AgentGuard 前端说明

这是 Agent-Authorization 项目的提交版前端，使用 React + Vite + TypeScript 实现。

前端目标是：**简洁展示 AI Agent 工具调用授权链路**，而不是做复杂后台系统。

---


## 启动方式

推荐从项目根目录启动：

```powershell
python .\start_project.py --clean
```

或单独启动前端：

```powershell
npm --prefix ".\frontend" install
npm --prefix ".\frontend" run dev
```

浏览器访问：

```text
http://localhost:5173
```

---

## 后端代理

前端默认通过 Vite proxy 调用后端：

```text
http://127.0.0.1:8000
```

主要接口包括：

```text
/tool-proxy/authorize
/gateway/check
/sandbox-native/*
/sandbox-docker/*
/test-results/*
/external-agent/*
```

---

## 构建

```powershell
npm --prefix ".\frontend" run build
```
