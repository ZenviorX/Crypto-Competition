# RESEARCH

状态：CONFIRMED + PROPOSED

## 已确认的研究边界

- 不能把“OAuth 只能做粗粒度 scope 授权”作为严格事实；现代 OAuth 体系已有 RAR、Resource Indicators 等细粒度机制。
- 不能把“OAuth + W3C VC”本身直接声称为项目创新；相关标准、草案和开源实现已经存在大量先行工作。
- MCP Authorization 已经把 OAuth 体系作为标准授权基础，因此“给 MCP 加 OAuth”属于基线能力，不是新颖点。

## 当前需要持续对比的先行工作

重点包括但不限于：OAuth RAR、Resource Indicators、MCP Authorization、W3C VC、OpenID4VP、OpenID4VCI、Agent Authorization 相关 IETF 草案、UCAN、GNAP、Agent Operation Authorization、Open Agent Auth、PAuth、ACLE-MCP。

## 当前候选研究问题

建立 OAuth/RAR 的 Requested/Granted 授权、VC/VP 可验证证据与 MCP `tools/call` 实际执行之间的机器可验证映射，使执行边界能够验证权限没有扩张、参数没有替换、主体/Holder 没有替换。

该研究问题仍需继续与最接近的先行工作做逐项差异分析后，才能形成最终创新声明。
