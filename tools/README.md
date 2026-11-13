# Strata vendored tools

Source snapshots of companion tools that feed the Strata pipeline.

| Tool | Language | Role in Strata |
|---|---|---|
| `aperture/` | Go | passive/active subdomain discovery sources |
| `triage-loom/` | Python | 5-stage triage + investigation ranking |

`jsast`, `vulnharvest`, `echoforge`, and `param-oracle` are already integrated
as Strata adapters/engines:

- `src/strata/adapters/jsast.py`
- `src/strata/adapters/vulnharvest.py`
- `src/strata/engines/echoforge.py`
- `src/strata/engines/param_oracle.py`

These folders are source snapshots, not installed packages. They are excluded
from Strata linting and packaging.
