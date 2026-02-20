import { NextResponse } from 'next/server';
import { prisma } from '../../../../lib/prisma';

export async function GET() {
    try {
        const [totalThreats, recentThreats, syncLogs, topSources] = await Promise.all([
            // Total threats in vault
            prisma.threatHash.count(),
            // Last 10 entries
            prisma.threatHash.findMany({
                orderBy: { createdAt: 'desc' },
                take: 10,
                select: { hash: true, source: true, confidence: true, createdAt: true }
            }),
            // Total syncs
            prisma.syncLog.count(),
            // Group by source
            prisma.threatHash.groupBy({
                by: ['source'],
                _count: { hash: true },
                orderBy: { _count: { hash: 'desc' } }
            })
        ]);

        return NextResponse.json({
            totalThreats,
            recentThreats,
            totalSyncs: syncLogs,
            sourceBreakdown: topSources.map(s => ({
                source: s.source,
                count: s._count.hash
            }))
        });
    } catch (e: any) {
        console.error('Vault stats error:', e);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
