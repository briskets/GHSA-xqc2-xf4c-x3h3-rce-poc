import { OperatorConsole } from './console';
import { getArtifactBlocks } from './payload';

// The page depends on the `annotation` query parameter, so it renders per
// request instead of being prerendered.
export const instant = false;

function describe(value) {
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return `Uint8Array(${value.length})`;
  if (value && typeof value === 'object') {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch {
      return String(value);
    }
  }
  return String(value);
}

async function ArtifactPreview({ annotation }) {
  const blocks = await getArtifactBlocks(annotation);

  // Cached entries can carry deferred values; resolve them before rendering.
  let resolved = blocks.annotation;
  try {
    resolved = await resolved;
  } catch (err) {
    resolved = `[unresolved: ${(err && err.message) || err}]`;
  }

  return (
    <pre>
      {JSON.stringify(
        {
          block0: blocks.block0?.length,
          block1: blocks.block1?.length,
          annotation: describe(resolved),
        },
        null,
        2
      )}
    </pre>
  );
}

export default async function Page({ searchParams }) {
  const params = await searchParams;
  const annotation = typeof params.annotation === 'string' ? params.annotation : null;

  return (
    <main>
      <h1>Artifact service</h1>
      <p>
        First two 8 KB blocks of the current artifact, plus the caller-supplied
        annotation.
      </p>
      {annotation === null ? (
        <p>
          Query an artifact with <code>?annotation=&lt;base64&gt;</code>.
        </p>
      ) : (
        <ArtifactPreview annotation={annotation} />
      )}
      <OperatorConsole />
    </main>
  );
}
