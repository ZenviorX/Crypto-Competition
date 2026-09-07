import type { Decision, RequestStatus, RiskLevel } from '../types/domain';

export const decisionText: Record<Decision, string> = {
  allow: '放行',
  deny: '拒绝',
  confirm: '确认',
  review: '复核'
};

export const riskText: Record<RiskLevel, string> = {
  low: '低风险',
  medium: '中风险',
  high: '高风险',
  critical: '严重风险'
};

export const statusText: Record<RequestStatus, string> = {
  pending: '待处理',
  approved: '已通过',
  rejected: '已拒绝',
  blocked: '已阻断'
};

export function compactNumber(value: number): string {
  return new Intl.NumberFormat('zh-CN').format(value);
}
