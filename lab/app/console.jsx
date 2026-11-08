'use client';

import { runMaintenanceJob } from './actions';

// The UI only ever sends the preset job id. The Server Action id still ships
// to every browser, which is enough for the PoC to find and invoke it.
export function OperatorConsole() {
  return (
    <section>
      <h2>Maintenance</h2>
      <button type="button" onClick={() => runMaintenanceJob('reindex')}>
        Reindex artifacts
      </button>
    </section>
  );
}
