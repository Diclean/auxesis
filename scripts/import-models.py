#!/usr/bin/env python3
"""Generate ``catalog/models.toml`` from the vendored ``catalog/models.dev.json``.

Offline only: this script never touches the network, and the app never fetches
models.dev at runtime (``docs/providers.md`` §4). Run it with::

    python3 -I scripts/import-models.py

The vendored JSON is the models.dev ``/api.json`` shape with a ``fetched``
date added::

    {"fetched": "2026-10-11",
     "providers": {"<provider>": {"models": {"<id>": {
         "tool_call": true, "structured_output": true,
         "limit": {"context": 1000000, "output": 128000},
         "cost": {"input": 4.0, "output": 20.0}}}}}}
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Providers billed by a flat subscription: the cost of one call is known to be
# 0 cents, so these rows carry `billing = "subscription"`. A row without a
# price is never assumed to be a subscription.
SUBSCRIPTION_PROVIDERS = {"ollama-cloud", "opencode-go"}

# Official list prices that models.dev lacks, in USD per million tokens, with
# where and when they were read. The peak-hour, cache-miss rate is used.
PRICE_OVERRIDES = {
    ("deepseek", "deepseek-flash"): (
        0.3,
        1.2,
        "https://api-docs.deepseek.com/quick_start/pricing, read 2026-11-04 "
        "(peak hours, input cache miss / output)",
    ),
}

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "catalog" / "models.dev.json"
OUTPUT = ROOT / "catalog" / "models.toml"


def toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)):
        return repr(value)
    raise TypeError(f"unsupported TOML value: {value!r}")


def main() -> int:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    providers = data.get("providers", {})
    fetched = data.get("fetched", "unknown")

    lines = [
        f"# Generated offline from catalog/models.dev.json (fetched {fetched}).",
        "# Run: python3 -I scripts/import-models.py. Do not edit by hand.",
        "",
    ]
    count = 0
    for provider_id in sorted(providers):
        models = providers[provider_id].get("models", {})
        for model_id in sorted(models):
            model = models[model_id]
            limit = model.get("limit") or {}
            cost = model.get("cost") or {}
            fields: list[tuple[str, object]] = [
                ("provider", provider_id),
                ("id", model_id),
                ("tools", bool(model.get("tool_call", model.get("tools", False)))),
                ("structured_output", bool(model.get("structured_output", False))),
            ]
            if limit.get("context") is not None:
                fields.append(("context", int(limit["context"])))
            if limit.get("output") is not None:
                fields.append(("output", int(limit["output"])))
            override = PRICE_OVERRIDES.get((provider_id, model_id))
            if override is not None:
                cost = {"input": override[0], "output": override[1]}
                lines.append(f"# Price: {override[2]}.")
            if cost.get("input") is not None:
                fields.append(("input_usd_mtok", float(cost["input"])))
            if cost.get("output") is not None:
                fields.append(("output_usd_mtok", float(cost["output"])))
            if provider_id in SUBSCRIPTION_PROVIDERS:
                fields.append(("billing", "subscription"))

            lines.append("[[model]]")
            for key, value in fields:
                lines.append(f"{key} = {toml_value(value)}")
            lines.append("")
            count += 1

    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUTPUT} ({count} models)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
