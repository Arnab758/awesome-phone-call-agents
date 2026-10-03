import { NextResponse } from 'next/server';
import { store } from '@/lib/store';
import { sanitizeRecordForDisplay } from '@/lib/phone-utils';

export async function GET(
  _req: Request,
  { params }: { params: { id: string } }
) {
  const record = store.getVerification(params.id);
  if (!record) {
    return NextResponse.json(
      { error: `Verification record "${params.id}" not found.` },
      { status: 404 }
    );
  }

  return NextResponse.json({
    record: sanitizeRecordForDisplay(record),
  });
}
