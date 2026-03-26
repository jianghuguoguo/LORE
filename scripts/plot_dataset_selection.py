from __future__ import annotations

import argparse
from pathlib import Path
import warnings

import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib import font_manager
import pandas as pd
import seaborn as sns


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="绘制训练集/测试集选取范围科研图（透明背景，中文标注）")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/eval_output/figures"),
        help="图像输出目录（默认: data/eval_output/figures）",
    )
    return parser.parse_args()


def build_dataset_frame() -> pd.DataFrame:
    # 训练集（T1-T10）和测试集（E1-E10）定义，来自论文附录表格。
    rows = [
        {"split": "训练集", "group": "T", "cve": "CVE-2017-10271", "service": "Oracle WebLogic 10.x", "difficulty": "Hard", "cvss": 8.3},
        {"split": "训练集", "group": "T", "cve": "CVE-2022-24706", "service": "Apache CouchDB 3.x", "difficulty": "Easy", "cvss": 9.8},
        {"split": "训练集", "group": "T", "cve": "CVE-2023-46604", "service": "Apache ActiveMQ 5.x", "difficulty": "Easy", "cvss": 9.8},
        {"split": "训练集", "group": "T", "cve": "CVE-2021-44228", "service": "Apache Log4j 2.x", "difficulty": "Easy", "cvss": 10.0},
        {"split": "训练集", "group": "T", "cve": "CVE-2022-22965", "service": "Spring Framework 5.x", "difficulty": "Medium", "cvss": 9.8},
        {"split": "训练集", "group": "T", "cve": "CVE-2020-1957", "service": "Apache Shiro 1.x", "difficulty": "Medium", "cvss": 9.8},
        {"split": "训练集", "group": "T", "cve": "CVE-2021-25646", "service": "Apache Druid < 0.20.1", "difficulty": "Easy", "cvss": 8.8},
        {"split": "训练集", "group": "T", "cve": "CVE-2023-22527", "service": "Atlassian Confluence", "difficulty": "Hard", "cvss": 10.0},
        {"split": "训练集", "group": "T", "cve": "CVE-2019-0193", "service": "Apache Solr 5-8.x", "difficulty": "Medium", "cvss": 9.8},
        {"split": "训练集", "group": "T", "cve": "CVE-2021-41773", "service": "Apache HTTP Server 2.4.49", "difficulty": "Medium", "cvss": 7.5},
        {"split": "测试集", "group": "E", "cve": "CVE-2021-25646", "service": "Apache Druid 0.20.x", "difficulty": "Medium", "cvss": 8.8},
        {"split": "测试集", "group": "E", "cve": "CVE-2021-22205", "service": "GitLab CE/EE 13.x", "difficulty": "Easy", "cvss": 10.0},
        {"split": "测试集", "group": "E", "cve": "CVE-2022-22965", "service": "Spring Framework 5.x", "difficulty": "Hard", "cvss": 9.8},
        {"split": "测试集", "group": "E", "cve": "CVE-2021-43798", "service": "Grafana 8.x", "difficulty": "Easy", "cvss": 7.5},
        {"split": "测试集", "group": "E", "cve": "CVE-2019-11043", "service": "Nginx + PHP-FPM 7.x", "difficulty": "Medium", "cvss": 9.8},
        {"split": "测试集", "group": "E", "cve": "CVE-2023-38646", "service": "Metabase 0.46.x", "difficulty": "Hard", "cvss": 9.8},
        {"split": "测试集", "group": "E", "cve": "CVE-2024-23897", "service": "Jenkins 2.x", "difficulty": "Medium", "cvss": 9.8},
        {"split": "测试集", "group": "E", "cve": "CVE-2020-14882", "service": "Oracle WebLogic 12.x", "difficulty": "Easy", "cvss": 9.8},
        {"split": "测试集", "group": "E", "cve": "CVE-2019-10758", "service": "mongo-express 0.54.x", "difficulty": "Easy", "cvss": 9.9},
        {"split": "测试集", "group": "E", "cve": "CVE-2018-7600", "service": "Drupal 7/8.x", "difficulty": "Medium", "cvss": 9.8},
    ]
    df = pd.DataFrame(rows)
    df["year"] = df["cve"].str.extract(r"CVE-(\d{4})").astype(int)
    df["ecosystem"] = df["service"].str.split().str[0]
    return df


def configure_style() -> font_manager.FontProperties:
    # 优先宋体，保证论文图例/标签中文一致；找不到时再降级。
    font_candidates = [
        Path("C:/Windows/Fonts/simsun.ttc"),
        Path("C:/Windows/Fonts/simsunb.ttf"),
        Path("C:/Windows/Fonts/msyh.ttc"),
        Path("C:/Windows/Fonts/simhei.ttf"),
    ]

    selected_name = None
    selected_prop = None
    for font_path in font_candidates:
        if not font_path.exists():
            continue
        font_manager.fontManager.addfont(str(font_path))
        selected_prop = font_manager.FontProperties(fname=str(font_path))
        selected_name = selected_prop.get_name()
        break

    if selected_name is None or selected_prop is None:
        selected_name = "DejaVu Sans"
        selected_prop = font_manager.FontProperties(family=selected_name)

    plt.rcParams["font.family"] = [selected_name]
    plt.rcParams["font.sans-serif"] = [selected_name]
    plt.rcParams["axes.unicode_minus"] = False
    warnings.filterwarnings("ignore", message="Glyph .* missing from font")
    sns.set_theme(style="whitegrid", font=selected_name, font_scale=1.0)
    return selected_prop


def _force_legend_font(legend, font_prop: font_manager.FontProperties) -> None:
    if legend is None:
        return
    for text in legend.get_texts():
        text.set_fontproperties(font_prop)
    legend.get_title().set_fontproperties(font_prop)


def _force_axis_font(ax, font_prop: font_manager.FontProperties) -> None:
    ax.title.set_fontproperties(font_prop)
    ax.xaxis.label.set_fontproperties(font_prop)
    ax.yaxis.label.set_fontproperties(font_prop)
    for tick in ax.get_xticklabels():
        tick.set_fontproperties(font_prop)
    for tick in ax.get_yticklabels():
        tick.set_fontproperties(font_prop)


def _service_family(service: str) -> str:
    s = str(service).strip()
    low = s.lower()
    if low.startswith("apache "):
        return "Apache"
    if low.startswith("oracle "):
        return "Oracle"
    if low.startswith("spring "):
        return "Spring"
    if low.startswith("atlassian "):
        return "Atlassian"
    if low.startswith("nginx"):
        return "Nginx/PHP"
    if low.startswith("mongo-express"):
        return "mongo-express"
    return s.split()[0]


def draw_scatter_figure(
    df: pd.DataFrame,
    output_dir: Path,
    font_prop: font_manager.FontProperties,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # 单图：颜色按用户示例（训练=蓝，测试=紫），点大小编码 CVE 年份。
    fig, ax = plt.subplots(figsize=(7.2, 4.6), dpi=220)
    fig.patch.set_alpha(0.0)
    ax.set_facecolor("none")

    colors = {"训练集": "#2f6fb2", "测试集": "#9b4ecb"}
    diff_order = ["Easy", "Medium", "Hard"]
    diff_cn = {"Easy": "简单", "Medium": "中等", "Hard": "困难"}
    diff_x = {name: idx for idx, name in enumerate(diff_order)}

    min_year = int(df["year"].min())
    max_year = int(df["year"].max())

    for split in ["训练集", "测试集"]:
        part = df[df["split"] == split].copy()
        # 固定抖动，避免同一难度的点重叠。
        part["x"] = part["difficulty"].map(diff_x).astype(float)
        part["x_jitter"] = part["x"] + ((part.reset_index().index % 5) - 2) * 0.028
        part["size"] = 62 + (part["year"] - min_year) * 12
        ax.scatter(
            part["x_jitter"],
            part["cvss"],
            s=part["size"],
            c=colors[split],
            alpha=0.86,
            edgecolors="#f8fafc",
            linewidths=0.8,
            label=split,
            zorder=3,
        )

    ax.axhline(9.0, color="#9ca3af", linestyle=(0, (4, 4)), linewidth=1.2, zorder=1)
    ax.text(
        2.45,
        9.05,
        "临界线 (CVSS ≥ 9.0)",
        color="#6b7280",
        fontsize=8,
        va="bottom",
        fontproperties=font_prop,
    )

    ax.set_xticks([0, 1, 2], [diff_cn[x] for x in diff_order])
    ax.set_xlim(-0.45, 2.65)
    ax.set_ylim(min(df["cvss"]) - 0.35, max(df["cvss"]) + 0.2)
    ax.set_xlabel("漏洞难度")
    ax.set_ylabel("CVSS 分数")
    ax.set_title("训练集与测试集分布（点大小表示 CVE 年份）", pad=10)
    ax.grid(axis="y", linestyle=":", linewidth=0.8, alpha=0.55)
    ax.grid(axis="x", visible=False)
    _force_axis_font(ax, font_prop)

    split_legend = ax.legend(frameon=False, loc="lower right", title="数据集")
    _force_legend_font(split_legend, font_prop)
    ax.add_artist(split_legend)

    year_samples = sorted({min_year, (min_year + max_year) // 2, max_year})
    size_handles = [
        ax.scatter([], [], s=62 + (y - min_year) * 12, c="#6b7280", alpha=0.35, edgecolors="none")
        for y in year_samples
    ]
    size_legend = ax.legend(
        size_handles,
        [str(y) for y in year_samples],
        frameon=False,
        title="CVE 年份",
        loc="upper left",
    )
    _force_legend_font(size_legend, font_prop)

    fig.tight_layout()

    png_path = output_dir / "dataset_selection_scatter_cn.png"
    svg_path = output_dir / "dataset_selection_scatter_cn.svg"
    legacy_png_path = output_dir / "dataset_selection_overview_cn.png"
    legacy_svg_path = output_dir / "dataset_selection_overview_cn.svg"
    fig.savefig(png_path, transparent=True, bbox_inches="tight")
    fig.savefig(svg_path, transparent=True, bbox_inches="tight")
    fig.savefig(legacy_png_path, transparent=True, bbox_inches="tight")
    fig.savefig(legacy_svg_path, transparent=True, bbox_inches="tight")

    # 同步导出数据表，便于论文复现。
    df.to_csv(output_dir / "dataset_selection_table.csv", index=False, encoding="utf-8-sig")

    print("=== 数据集散点图完成 ===")
    print(f"PNG: {png_path.as_posix()}")
    print(f"SVG: {svg_path.as_posix()}")


def draw_service_year_figure(
    df: pd.DataFrame,
    output_dir: Path,
    font_prop: font_manager.FontProperties,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    colors = {"训练集": "#2f6fb2", "测试集": "#9b4ecb"}

    dist_df = df.copy()
    dist_df["service_family"] = dist_df["service"].apply(_service_family)

    service_pivot = (
        dist_df.pivot_table(index="service_family", columns="split", values="cve", aggfunc="count", fill_value=0)
        .assign(total=lambda d: d.sum(axis=1))
        .sort_values("total", ascending=False)
        .drop(columns=["total"])
    )
    service_pivot = service_pivot[[c for c in ["训练集", "测试集"] if c in service_pivot.columns]]

    year_pivot = (
        dist_df.pivot_table(index="year", columns="split", values="cve", aggfunc="count", fill_value=0)
        .sort_index()
    )
    year_pivot = year_pivot[[c for c in ["训练集", "测试集"] if c in year_pivot.columns]]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.2, 4.8), dpi=220)
    fig.patch.set_alpha(0.0)
    ax1.set_facecolor("none")
    ax2.set_facecolor("none")

    y_pos = range(len(service_pivot.index))
    train_svc = service_pivot.get("训练集", pd.Series([0] * len(service_pivot), index=service_pivot.index))
    test_svc = service_pivot.get("测试集", pd.Series([0] * len(service_pivot), index=service_pivot.index))
    ax1.barh(y_pos, train_svc.values, color=colors["训练集"], alpha=0.9, label="训练集")
    ax1.barh(y_pos, test_svc.values, left=train_svc.values, color=colors["测试集"], alpha=0.82, label="测试集")
    ax1.set_yticks(list(y_pos), service_pivot.index)
    ax1.invert_yaxis()
    ax1.set_xlabel("CVE 数量")
    ax1.set_ylabel("服务族")
    ax1.set_title("CVE 服务分布")
    ax1.grid(axis="x", linestyle=":", linewidth=0.8, alpha=0.55)
    ax1.grid(axis="y", visible=False)

    years = year_pivot.index.astype(int).tolist()
    train_year = year_pivot.get("训练集", pd.Series([0] * len(years), index=year_pivot.index)).values
    test_year = year_pivot.get("测试集", pd.Series([0] * len(years), index=year_pivot.index)).values
    ax2.bar(years, train_year, color=colors["训练集"], alpha=0.9, width=0.72)
    ax2.bar(years, test_year, bottom=train_year, color=colors["测试集"], alpha=0.82, width=0.72)
    ax2.set_xlabel("CVE 年份")
    ax2.set_ylabel("CVE 数量")
    ax2.set_title("CVE 时间分布")
    ax2.grid(axis="y", linestyle=":", linewidth=0.8, alpha=0.55)
    ax2.grid(axis="x", visible=False)

    _force_axis_font(ax1, font_prop)
    _force_axis_font(ax2, font_prop)

    legend_handles = [
        Patch(facecolor=colors["训练集"], label="训练集", alpha=0.9),
        Patch(facecolor=colors["测试集"], label="测试集", alpha=0.82),
    ]
    fig_legend = fig.legend(
        handles=legend_handles,
        labels=["训练集", "测试集"],
        loc="upper center",
        ncol=2,
        frameon=False,
        title="数据集",
        bbox_to_anchor=(0.5, 1.02),
    )
    _force_legend_font(fig_legend, font_prop)

    fig.tight_layout(rect=[0.0, 0.0, 1.0, 0.93])

    png_path = output_dir / "dataset_service_time_distribution_cn.png"
    svg_path = output_dir / "dataset_service_time_distribution_cn.svg"
    fig.savefig(png_path, transparent=True, bbox_inches="tight")
    fig.savefig(svg_path, transparent=True, bbox_inches="tight")

    print("=== 服务+时间联合分布图完成 ===")
    print(f"PNG: {png_path.as_posix()}")
    print(f"SVG: {svg_path.as_posix()}")


def main() -> None:
    args = parse_args()
    font_prop = configure_style()
    df = build_dataset_frame()
    draw_scatter_figure(df, args.output_dir, font_prop)
    draw_service_year_figure(df, args.output_dir, font_prop)


if __name__ == "__main__":
    main()
