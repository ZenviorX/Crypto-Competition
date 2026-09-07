import { useMemo, useState } from 'react';
import type { GatewayRequest, RequestStatus, RiskLevel } from '../types/domain';
import { RequestTable } from '../components/RequestTable';
import { Section } from '../components/Section';

interface RequestsPageProps {
  requests: GatewayRequest[];
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
}

export function RequestsPage({ requests, onApprove, onReject }: RequestsPageProps) {
  const [keyword, setKeyword] = useState('');
  const [risk, setRisk] = useState<RiskLevel | 'all'>('all');
  const [status, setStatus] = useState<RequestStatus | 'all'>('all');

  const filtered = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    return requests.filter((item) => {
      const hitKeyword = !kw || [item.id, item.agent, item.user, item.tool, item.target, item.reason, item.policy]
        .some((field) => field.toLowerCase().includes(kw));
      return hitKeyword && (risk === 'all' || item.risk === risk) && (status === 'all' || item.status === status);
    });
  }, [keyword, requests, risk, status]);

  return (
    <Section
      eyebrow="Request Center"
      title="请求审查中心"
      description="用于处理 confirm / review 类型请求，也可以查看 deny 的拦截原因。"
      actions={<span className="result-count">共 {filtered.length} 条</span>}
    >
      <div className="filter-bar">
        <input value={keyword} onChange={(e) => setKeyword(e.target.value)} placeholder="搜索请求 ID、智能体、工具、策略……" />
        <select value={risk} onChange={(e) => setRisk(e.target.value as RiskLevel | 'all')}>
          <option value="all">全部风险</option>
          <option value="low">低风险</option>
          <option value="medium">中风险</option>
          <option value="high">高风险</option>
          <option value="critical">严重风险</option>
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value as RequestStatus | 'all')}>
          <option value="all">全部状态</option>
          <option value="pending">待处理</option>
          <option value="approved">已通过</option>
          <option value="rejected">已拒绝</option>
          <option value="blocked">已阻断</option>
        </select>
      </div>
      <RequestTable rows={filtered} onApprove={onApprove} onReject={onReject} />
    </Section>
  );
}
