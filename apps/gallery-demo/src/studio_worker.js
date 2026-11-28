// Zyoza Studio prover worker. Runs the WebAssembly prover off the page's main thread, so the
// page stays responsive while a proof is computed. The lineage proof lives here, in this
// browser tab, and is never sent to the server.
//
// The server fills in __PROVER_DIR__ with a path that contains a hash of the prover build, so
// the browser can cache those files for good and still pick up a new build immediately.
import init, { warmup, run_job, promote, discard, has_lineage, forget_all } from '__PROVER_DIR__/zyoza_studio_prover.js';

const started = performance.now();
const stage = (name) => self.postMessage({ progress: name, ms: Math.round(performance.now() - started) });
// Called from inside the prover as warm-up passes each stage ("registry", then "ready").
globalThis.zyozaProverStage = stage;

let ready = null;
function boot() {
  if (!ready) {
    ready = (async () => {
      await init();
      stage('loaded');
      const t0 = performance.now();
      warmup();
      return { warmup_ms: Math.round(performance.now() - t0), total_ms: Math.round(performance.now() - started) };
    })();
  }
  return ready;
}

self.onmessage = async (ev) => {
  const { id, op, arg } = ev.data;
  try {
    const boot_info = await boot();
    let result;
    if (op === 'warmup') result = boot_info;
    else if (op === 'run') {
      const t0 = performance.now();
      const output = JSON.parse(run_job(JSON.stringify(arg)));
      result = { output, prove_ms: Math.round(performance.now() - t0) };
    } else if (op === 'promote') result = promote(arg);
    else if (op === 'discard') result = discard(arg);
    else if (op === 'has_lineage') result = has_lineage(arg);
    else if (op === 'forget_all') result = forget_all();
    else throw new Error('unknown prover op: ' + op);
    self.postMessage({ id, ok: true, result });
  } catch (e) {
    self.postMessage({ id, ok: false, error: (e && e.message) ? e.message : String(e) });
  }
};
