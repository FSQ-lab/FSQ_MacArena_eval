# FSQ_MacArena_eval

Official [MacPaw/MacArena](https://github.com/MacPaw/MacArena) macOS evaluation harness for native `FSQ` (`fsq-agent` + `appium-connect-agent` + `Appium Mac2`).

## Architecture & Guarantees

- **Zero Editable Subject Packages**: The default freeze uses the following official PyPI wheels:
  - `appium_connect_agent-0.1.4-py3-none-any.whl` (`18e53b29d80fcf0bedbf65e600dc7342643cb1de6539c78131b4860978dee62b`, commit `4707aec198c34264ab8dc1178005a45aa5a5bd41`)
  - `fsq_agent-0.3.9-py3-none-any.whl` (`6c7993100e25dcb6dcdfbd1abc22f51e58c12b21e89b61c1dfbfe55322e3bd03`, commit `aa3aeea1853deff7872f063d53259b84fa877d80`)
  - Pin `lxml==6.1.0` in the host environment and guest worker venv.
- **Dual-VM Concurrency (`--workers 2`)**: Apple `Virtualization.framework` supports up to 2 concurrent macOS guests. Each worker slot clones an APFS CoW ephemeral VM, assigns a unique locally-administered MAC on the **cloned** `config.plist` (never mutating the Golden Base VM), boots, runs setup, executes the isolated guest `fsq_worker.py` over `ssh -R 17877:127.0.0.1:7877` with `NO_PROXY=127.0.0.1,localhost,::1`, runs the official MacArena evaluator (`:5000`), and deletes the disposable VM.
- **Fair Initial Target Contract**: Runs default to `bundle_id="auto"` (native frontmost resolution after upstream setup), without leaking `related_apps` or pre-launching task applications on behalf of the subject.

Pass `--utm-documents-dir <baked-copy-directory>` before `run` to clone verified release copies instead of the default `vm_golden/` bundles.

`run` and `smoke-6` deny visual provider upload by default. Use `--allow-visual-provider-upload` only for non-sensitive fixtures when the host authorizes model access to frames. The native per-frame resolver remains a separate gate. Local observations such as `sample_color` are read-only and do not consume the write budget. Campaign resume does not reuse episodes with missing or different upload authorization.

Stage the two exact [SDK](https://pypi.org/project/appium-connect-agent/0.1.4/#files) and [FSQ](https://pypi.org/project/fsq-agent/0.3.9/#files) wheels in `artifacts/state/pypi-sdk014-fsq039/` and run `fsq-macarena-eval verify-freeze` from the evaluation workspace root. The default freeze does not download wheels or fall back to candidate artifacts.

Updating the host freeze does not update existing baked guests. Use a release-matched VM copy or install the frozen subject wheels plus a matching Eval worker into a disposable clone. Install from the exact local wheel files and retain them: the runner checks both the installed archive provenance and the bytes. Use a new campaign directory after changing the wheel freeze. The Phase 2 candidate launchers are historical and not used by the release freeze.
