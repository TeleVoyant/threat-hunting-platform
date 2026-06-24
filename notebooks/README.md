# Detector Experimentation Notebooks

Working/lab notebooks documenting how the two XGBoost detectors
(`lateral_movement`, `dns_exfiltration`) were experimented with and tuned. They call the
**same** production code in `training/`, `features/`, and `detection/` — so what is tuned here
is exactly what the platform deploys (train/serve parity).

| Notebook | Covers (workflow doc) |
|---|---|
| `01_training_experimentation.ipynb` | Data generation, the 156-feature pipeline, **feature-domain restriction** experiment, `GridSearchCV` hyperparameter tuning, NFR-02 evaluation, and **XGBoost learning curves** — maps to `training-workflow.md` |
| `02_detection_experimentation.ipynb` | Batched inference + feature-schema pin, **SHAP** explainability, threshold/severity laddering, and **drift monitoring** — maps to `detection-workflow.md` |

## Running them

Everything runs **offline** against the synthetic event generator — **no Wazuh / Docker stack
is required**.

```bash
# from the repo root (threat-hunting-platform/)
OMP_NUM_THREADS=1 venv/bin/jupyter lab notebooks/
```

Then **run `01_…` before `02_…`** — notebook 1 saves the trained candidate models into
`notebooks/artifacts/`, which notebook 2 loads for the inference/SHAP/drift experiments.

To re-execute headless and confirm every cell still runs clean:

```bash
OMP_NUM_THREADS=1 venv/bin/jupyter nbconvert --to notebook --execute --inplace \
    notebooks/01_training_experimentation.ipynb
OMP_NUM_THREADS=1 venv/bin/jupyter nbconvert --to notebook --execute --inplace \
    notebooks/02_detection_experimentation.ipynb
```

### Notes
- `OMP_NUM_THREADS=1` avoids the XGBoost/OpenMP segfault documented in `training-workflow.md`
  ("Sandbox note"). The notebooks also pin the other native thread pools in their first cell.
- `notebooks/artifacts/` holds generated outputs (trained `*.json` models, the tuning result,
  and the drift baseline). It is safe to delete — notebook 1 regenerates it.
- These notebooks are **experimentation logs**, not the production training path. The deployed
  models are produced by `python -m training.train_models` (see `training-workflow.md`).
