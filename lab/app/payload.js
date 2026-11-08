// Cached artifact lookup.
//
// Returns the first two 8 KB blocks of the artifact — two partial views over one
// shared ArrayBuffer — plus the caller's annotation.
//
// On react-server-dom-* 19.3.0 the first view detaches the shared buffer, so the
// second block is written with its header but no payload.
export async function getArtifactBlocks(annotationB64) {
  'use cache';

  const buf = new ArrayBuffer(16384);
  const block0 = new Uint8Array(buf, 0, 8192);
  const block1 = new Uint8Array(buf, 8192, 8192);
  block0.fill(0x41);
  block1.fill(0x42);

  const annotation = new Uint8Array(Buffer.from(annotationB64 || '', 'base64'));
  return { block0, block1, annotation };
}
