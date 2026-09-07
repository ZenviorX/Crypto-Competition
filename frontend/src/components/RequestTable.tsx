import type { GatewayRequest } from '../types/domain';
import { decisionText, riskText, statusText } from '../utils/format';
import { Badge } from './Badge';

interface RequestTableProps {
  rows: GatewayRequest[];
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
  compact?: boolean;
  evidenceLayout?: boolean;
}

const riskTone = {
  low: 'green',
  medium: 'yellow',
  high: 'red',
  critical: 'red'
} as const;

const decisionTone = {
  allow: 'green',
  deny: 'red',
  confirm: 'yellow',
  review: 'purple'
} as const;

function shortenReference(value: string, head = 10, tail = 8) {
  if (!value || value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function looksLikeHash(value: string) {
  return /^[a-f0-9]{40,}$/i.test(value || '');
}

function compactReason(value: string, maxLength = 150) {
  if (!value || value.length <= maxLength) return value;
  return `${value.slice(0, maxLength).trim()}…`;
}

export function RequestTable({
  rows,
  onApprove,
  onReject,
  compact = false,
  evidenceLayout = false
}: RequestTableProps) {
  const showActions = Boolean(onApprove || onReject);
  const columnCount = (compact ? 6 : 7) + (showActions ? 1 : 0);

  return (
    <div className={`table-wrap${evidenceLayout ? ' evidence-table-wrap' : ''}`}>
      <table className={`data-table${evidenceLayout ? ' evidence-request-table' : ''}`}>
        <thead>
          <tr>
            <th>请求</th>
            <th>智能体 / 用户</th>
            <th>工具与目标</th>
            {!compact && (
              <th>{evidenceLayout ? '审计哈希 / 裁定依据' : '策略解释'}</th>
            )}
            <th>风险</th>
            <th>决策</th>
            <th>状态</th>
            {showActions && <th>操作</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td className={evidenceLayout ? 'request-ref-cell' : undefined}>
                <strong title={row.id}>
                  {evidenceLayout ? shortenReference(row.id, 9, 6) : row.id}
                </strong>
                <span>{row.createdAt}</span>
              </td>
              <td>
                <strong>{row.agent}</strong>
                <span>{row.user}</span>
              </td>
              <td>
                <strong>{row.tool}</strong>
                <span>{row.target}</span>
              </td>
              {!compact && (
                <td className={`wide-cell${evidenceLayout ? ' evidence-policy-cell' : ''}`}>
                  <strong title={row.policy}>
                    {evidenceLayout && looksLikeHash(row.policy)
                      ? `审计哈希 ${shortenReference(row.policy, 10, 8)}`
                      : row.policy}
                  </strong>

                  <span title={row.reason}>
                    {evidenceLayout
                      ? compactReason(row.reason)
                      : row.reason}
                  </span>
                </td>
              )}
              <td><Badge tone={riskTone[row.risk]}>{riskText[row.risk]}</Badge></td>
              <td><Badge tone={decisionTone[row.decision]}>{decisionText[row.decision]}</Badge></td>
              <td><Badge>{statusText[row.status]}</Badge></td>
              {showActions && (
                <td>
                  {row.status === 'pending' ? (
                    <div className="row-actions">
                      <button className="tiny-btn success" onClick={() => onApprove?.(row.id)}>通过</button>
                      <button className="tiny-btn danger" onClick={() => onReject?.(row.id)}>拒绝</button>
                    </div>
                  ) : (
                    <span className="muted">完成</span>
                  )}
                </td>
              )}
            </tr>
          ))}
          {!rows.length && (
            <tr>
              <td className="table-empty-cell" colSpan={columnCount}>
                暂无真实运行记录。前往“实时演示”发起一次任务后，本表会自动更新。
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
