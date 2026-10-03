"""scripts/eval_metrics.py — Binary-classification metrics for the evaluation (no side effects)."""

from __future__ import annotations


def confusion(pairs: list[tuple[bool, bool]]) -> dict:
    """pairs = [(truth, predicted)]. Undefined ratios are None (never invented)."""
    tp = sum(t and p for t, p in pairs)
    tn = sum(not t and not p for t, p in pairs)
    fp = sum(not t and p for t, p in pairs)
    fn = sum(t and not p for t, p in pairs)

    def ratio(a: int, b: int) -> float | None:
        return round(a / b, 4) if b else None

    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = round(2 * precision * recall / (precision + recall), 4)
    return {"n": len(pairs), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "accuracy": ratio(tp + tn, len(pairs)), "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": ratio(fp, fp + tn), "false_negative_rate": ratio(fn, fn + tp)}
