from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm


# =========================
# 1. 中文字体设置
# =========================
def setup_chinese_font():
    candidates = [
        "Microsoft YaHei",
        "SimHei",
        "Noto Sans CJK SC",
        "WenQuanYi Micro Hei",
        "PingFang SC",
        "Songti SC",
        "Arial Unicode MS",
    ]

    available = {f.name for f in fm.fontManager.ttflist}
    for name in candidates:
        if name in available:
            plt.rcParams["font.sans-serif"] = [name]
            break

    plt.rcParams["axes.unicode_minus"] = False


# =========================
# 2. 使用报告表 7-3 的实验数据
# =========================
data = {
    "allow_all": {
        "总体一致率": 21.43,
        "攻击阻断/确认率": 0.00,
        "攻击误放行率": 100.00,
        "平均延迟": 0.000,
    },
    "keyword": {
        "总体一致率": 74.29,
        "攻击阻断/确认率": 75.51,
        "攻击误放行率": 24.49,
        "平均延迟": 0.004,
    },
    "gateway": {
        "总体一致率": 100.00,
        "攻击阻断/确认率": 100.00,
        "攻击误放行率": 0.00,
        "平均延迟": 0.115,
    },
}


# =========================
# 3. 开始画图
# =========================
setup_chinese_font()

out_dir = Path("report_figures")
out_dir.mkdir(exist_ok=True)

metrics = ["总体一致率", "攻击阻断/确认率", "攻击误放行率"]

strategies = ["allow_all", "keyword", "gateway"]
strategy_names = {
    "allow_all": "无防护策略\nallow_all",
    "keyword": "关键词基线\nkeyword",
    "gateway": "本项目网关\ngateway",
}

x = np.arange(len(metrics))
width = 0.24

fig, ax = plt.subplots(figsize=(9.5, 5.6), dpi=300)

colors = ["#d9d9d9", "#a6a6a6", "#4d4d4d"]
hatches = ["", "//", "\\\\"]

for i, strategy in enumerate(strategies):
    values = [data[strategy][metric] for metric in metrics]
    bars = ax.bar(
        x + (i - 1) * width,
        values,
        width,
        label=strategy_names[strategy],
        color=colors[i],
        edgecolor="black",
        linewidth=0.8,
        hatch=hatches[i],
    )

    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + 2,
            f"{height:.1f}%",
            ha="center",
            va="bottom",
            fontsize=8,
        )

ax.set_title("不同工具调用防护策略的安全效果对比", fontsize=15, fontweight="bold", pad=14)
ax.set_ylabel("比例 / %", fontsize=11)
ax.set_xticks(x)
ax.set_xticklabels(metrics, fontsize=10)
ax.set_ylim(0, 115)
ax.grid(axis="y", linestyle="--", linewidth=0.6, alpha=0.5)

ax.legend(
    frameon=False,
    fontsize=9,
    ncol=3,
    loc="upper center",
    bbox_to_anchor=(0.5, -0.13),
)

latency_text = (
    "平均检测延迟："
    f"allow_all = {data['allow_all']['平均延迟']:.3f} ms；"
    f"keyword = {data['keyword']['平均延迟']:.3f} ms；"
    f"gateway = {data['gateway']['平均延迟']:.3f} ms"
)

ax.text(
    0.5,
    -0.27,
    latency_text,
    transform=ax.transAxes,
    ha="center",
    va="top",
    fontsize=9,
)

ax.text(
    0.5,
    -0.34,
    "说明：攻击阻断/确认率越高越好；攻击误放行率越低越好。",
    transform=ax.transAxes,
    ha="center",
    va="top",
    fontsize=9,
)

plt.tight_layout()

png_path = out_dir / "fig1_strategy_comparison.png"
pdf_path = out_dir / "fig1_strategy_comparison.pdf"

plt.savefig(png_path, bbox_inches="tight")
plt.savefig(pdf_path, bbox_inches="tight")

print("已生成：", png_path)
print("已生成：", pdf_path)