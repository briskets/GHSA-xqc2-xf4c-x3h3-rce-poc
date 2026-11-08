import { NextResponse } from 'next/server';
import { getArtifactBlocks } from '../../payload';

// Health/diagnostics endpoint. With no annotation it calls the cached lookup
// with an empty payload, so a broken read-back shows up as an error here.
export async function GET(request) {
  void request.url;

  try {
    const blocks = await getArtifactBlocks('');
    return NextResponse.json({
      ok: true,
      block0: blocks.block0?.length,
      block1: blocks.block1?.length,
      first0: blocks.block0?.[0],
      first1: blocks.block1?.[0],
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: String((err && err.message) || err) },
      { status: 500 }
    );
  }
}
