import type { GatewayRequest } from '../types/domain';
import { decisionText, riskText, statusText } from '../utils/format';
import { Badge } from './Badge';

interface RequestTableProps {
  rows: GatewayRequest[];
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
  compact?: boolean;
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

export function RequestTable({ rows, onApprove, onReject, compact = false }: RequestTableProps) {
  const showActions = Boolean(onApprove || onReject);
  const columnCount = (compact ? 6 : 7) + (showActions ? 1 : 0);

  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th>请求</th>
            <th>智能体 / 用户</th>
            <th>工具与目标</th>
            {!compact && <th>策略解释</th>}
            <th>风险</th>
            <th>决策</th>
            <th>状态</th>
            {showActions && <th>操作</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>
                <strong>{row.id}</strong>
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
                <td className="wide-cell">
                  <strong>{row.policy}</strong>
                  <span>{row.reason}</span>
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
