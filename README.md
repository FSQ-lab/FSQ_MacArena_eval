# FSQ_MacArena_eval

Official [MacPaw/MacArena](https://github.com/MacPaw/MacArena) macOS evaluation harness for native `FSQ` (`fsq-agent` + `appium-connect-agent` + `Appium Mac2`).

## Architecture & Guarantees

- **Zero Editable Subject Packages**: Guest workers install only SHA256-verified frozen wheels:
  - `appium_connect_agent-0.1.2-py3-none-any.whl` (`a6ac14573157138ff9140995f28081abf14114e3af794388f92cb9ab1692ec30`, commit `65363e7eae6310acf365dee652da7592196b6bb2`)
  - `fsq_agent-0.3.8-py3-none-any.whl` (`2927a13d5bca6e7e836cf0f7c9761840aaa17221bc4df7b3413a3ab2de69cbb7`, commit `761342030e545b1447420b282d35c2410d40e07d`)
  - Pin `lxml==6.1.0` in the host environment and guest worker venv.
- **Dual-VM Concurrency (`--workers 2`)**: Apple `Virtualization.framework` supports up to 2 concurrent macOS guests. Each worker slot clones an APFS CoW ephemeral VM, assigns a unique locally-administered MAC on the **cloned** `config.plist` (never mutating the Golden Base VM), boots, runs setup, executes the isolated guest `fsq_worker.py` over `ssh -R 17877:127.0.0.1:7877` with `NO_PROXY=127.0.0.1,localhost,::1`, runs the official MacArena evaluator (`:5000`), and deletes the disposable VM.
- **Fair Initial Target Contract**: Runs default to `bundle_id="auto"` (native frontmost resolution after upstream setup), without leaking `related_apps` or pre-launching task applications on behalf of the subject.

Pass `--utm-documents-dir <baked-copy-directory>` before `run` to clone verified release copies instead of the default `vm_golden/` bundles.

`run` and `smoke-6` deny visual provider upload by default. Use `--allow-visual-provider-upload` only for non-sensitive fixtures when the host authorizes model access to frames. The native per-frame resolver remains a separate gate. Local observations such as `sample_color` are read-only and do not consume the write budget. Campaign resume does not reuse episodes with missing or different upload authorization.

Use a matching guest worker wheel with this host request contract. Legacy baked guest workers reject the new request field; candidate validation installs the matching worker only in the disposable clone.

Local candidate integration is staged by `artifacts/state/phase2b-validation/run_candidates.py`: wheel checks are offline by default, and VM execution requires `--execute`. It installs SHA-verified wheels only on disposable clones, serially, and never bakes a base image.
