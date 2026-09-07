import type { SystemSetting } from '../types/domain';
import { Section } from '../components/Section';

export function SettingsPage({ settings }: { settings: SystemSetting[] }) {
  return (
    <Section
      eyebrow="System"
      title="系统设置"
      description="这里先做展示型设置框架，后续可以接入后端配置文件。"
      actions={<button className="primary-btn small">保存配置</button>}
    >
      <div className="settings-grid">
        {settings.map((item) => (
          <label className="setting-card" key={item.key}>
            <span>{item.name}</span>
            <input defaultValue={item.value} />
            <small>{item.description}</small>
          </label>
        ))}
      </div>
    </Section>
  );
}
