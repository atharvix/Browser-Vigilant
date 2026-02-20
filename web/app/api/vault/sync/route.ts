import { NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';

export async function GET(req: Request) {
    try {
        const { searchParams } = new URL(req.url);
        const since = searchParams.get('since');
        const clientId = searchParams.get('clientId') || 'anonymous';

        let whereClause = {};
        if (since) {
            const sinceDate = new Date(parseInt(since, 10));
            if (!isNaN(sinceDate.getTime())) {
                whereClause = {
                    updatedAt: { gte: sinceDate }
                };
            }
        }

        // Fetch all active threat hashes
        const threats = await prisma.threatHash.findMany({
            where: whereClause,
            select: {
                hash: true,
            },
            orderBy: {
                updatedAt: 'desc'
            }
        });

        const hashes = threats.map(t => t.hash);

        // Optionally record that a sync happens
        await prisma.syncLog.create({
            data: {
                clientId,
                hashCount: hashes.length
            }
        });

        return NextResponse.json({
            success: true,
            count: hashes.length,
            hashes: hashes,
            timestamp: Date.now()
        }, { status: 200 });

    } catch (e: any) {
        console.error("Vault sync error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}
