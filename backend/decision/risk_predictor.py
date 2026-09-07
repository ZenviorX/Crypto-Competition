from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


MODEL_PATH = (
    Path(__file__).resolve().parents[2]
    / "research"
    / "models"
    / "risk_model.json"
)


@dataclass
class RiskPrediction:
    """
    风险概率模型的统一输出。

    probability_unsafe:
        P(Y=unsafe | x)

    注意：
    这里的 probability_unsafe 必须来自训练后的模型。
    在模型尚未训练时，不允许人为填写一个假概率。
    """

    probability_unsafe: Optional[float]
    model_ready: bool
    model_version: str
    calibrated: bool
    warnings: List[str] = field(
        default_factory=list
    )


def _sigmoid(value: float) -> float:
    """
    Logistic Regression 的 sigmoid：
        p = 1 / (1 + exp(-z))
    """

    if value >= 0:
        exp_neg = math.exp(-value)
        return 1.0 / (1.0 + exp_neg)

    exp_pos = math.exp(value)
    return exp_pos / (1.0 + exp_pos)


def _load_model() -> Optional[Dict]:
    """
    加载训练后保存的 Logistic Regression 参数。

    模型文件不存在时返回 None。
    """

    if not MODEL_PATH.exists():
        return None

    try:
        with open(
            MODEL_PATH,
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return None

        return data

    except Exception:
        return None


def predict_unsafe_probability(
    features: Dict[str, float],
) -> RiskPrediction:
    """
    根据风险证据特征预测：

        P(unsafe | x)

    当前阶段如果模型还没有训练，
    会明确返回 model_ready=False。

    不允许退化成手工风险加分。
    """

    model = _load_model()

    if model is None:
        return RiskPrediction(
            probability_unsafe=None,
            model_ready=False,
            model_version="untrained",
            calibrated=False,
            warnings=[
                "风险概率模型尚未训练。",
                "当前不能产生 P(unsafe|x)，禁止使用人工风险分伪装成概率。",
            ],
        )

    feature_names = model.get(
        "feature_names",
        [],
    )

    coefficients = model.get(
        "coefficients",
        {},
    )

    intercept = float(
        model.get(
            "intercept",
            0.0,
        )
    )

    if not feature_names:
        return RiskPrediction(
            probability_unsafe=None,
            model_ready=False,
            model_version=str(
                model.get(
                    "model_version",
                    "invalid",
                )
            ),
            calibrated=False,
            warnings=[
                "模型文件缺少 feature_names。"
            ],
        )

    z = intercept

    missing_features: List[str] = []

    for feature_name in feature_names:
        if feature_name not in features:
            missing_features.append(
                feature_name
            )

        feature_value = float(
            features.get(
                feature_name,
                0.0,
            )
        )

        coefficient = float(
            coefficients.get(
                feature_name,
                0.0,
            )
        )

        z += (
            feature_value
            * coefficient
        )

    raw_probability = _sigmoid(z)

    # ---------------------------------------------------------
    # 当前第一版先支持未校准 Logistic Regression。
    # 后续我们会在独立 calibration set 上增加概率校准。
    # ---------------------------------------------------------
    calibrated = bool(
        model.get(
            "calibrated",
            False,
        )
    )

    warnings: List[str] = []

    if missing_features:
        warnings.append(
            "输入缺少模型所需特征："
            + ", ".join(
                missing_features
            )
        )

    if not calibrated:
        warnings.append(
            "当前概率尚未经过独立校准集校准。"
        )

    return RiskPrediction(
        probability_unsafe=max(
            0.0,
            min(
                1.0,
                raw_probability,
            ),
        ),
        model_ready=True,
        model_version=str(
            model.get(
                "model_version",
                "unknown",
            )
        ),
        calibrated=calibrated,
        warnings=warnings,
    )
