# 两阶段授权演示说明

Prepare 阶段只做授权判断，不执行工具。

Execute 阶段必须携带 Capability Token，校验通过后才真正执行工具。

Replay 阶段再次使用同一个 Token 会被拒绝，说明系统具备防重放能力。

正常演示结果：

Prepare: allow
Execute: allow
Replay: deny
