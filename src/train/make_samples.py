"""Cut sample/test files from the held-out UNSW-NB15 capture (part 1, never seen during training).

The default samples are enriched with attacks so the statistics have something to show. The
"realistic" file keeps attacks near 3% of the traffic, closer to what a real network looks like.
Formats vary on purpose so every upload path can be exercised.
"""

from __future__ import annotations

import pandas as pd

from train.train import PARTS, ROOT, fetch

PER_CATEGORY = 150
BENIGN = 3500


def _pick(df: pd.DataFrame, per_category: int, benign: int, seed: int = 7) -> pd.DataFrame:
    attacks = df[df["label"] == 1]
    picked = pd.concat(
        [g.sample(min(len(g), per_category), random_state=seed) for _, g in attacks.groupby("attack_cat")]
        + [df[df["label"] == 0].sample(benign, random_state=seed)]
    )
    return picked.sort_values("Stime")


def main() -> None:
    df = pd.read_parquet(fetch(PARTS["part1"]))
    df["attack_cat"] = df["attack_cat"].astype("string").str.strip().replace({"Backdoors": "Backdoor"})
    out = ROOT / "samples"
    out.mkdir(exist_ok=True)

    base = _pick(df, PER_CATEGORY, BENIGN)
    base.to_csv(out / "sample_labelled.csv", index=False)
    base.drop(columns=["attack_cat", "label"]).to_csv(out / "sample_unlabelled.csv", index=False)

    realistic = _pick(df, 60, 20000, seed=11)
    realistic.to_csv(out / "sample_realistic_3pct_attacks.csv", index=False)

    small = _pick(df, 40, 800, seed=3)
    small.to_csv(out / "sample_headerless_raw.csv", index=False, header=False)  # original UNSW-NB15 file style
    small.to_json(out / "sample_flows.ndjson", orient="records", lines=True)
    small.to_parquet(out / "sample_flows.parquet", index=False)

    for name, frame in [("labelled", base), ("realistic", realistic), ("small", small)]:
        print(f"{name}: {len(frame):,} rows, {int(frame['label'].sum()):,} attacks ({frame['label'].mean():.1%})")


if __name__ == "__main__":
    main()
