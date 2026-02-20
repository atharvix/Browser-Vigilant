import { NextResponse } from 'next/server';
import { prisma } from '../../../../lib/prisma';

export async function POST(req: Request) {
    try {
        const body = await req.json();
        const { hash, source, confidence, threatType } = body;

        if (!hash || typeof hash !== 'string' || hash.length !== 64) {
            return NextResponse.json({ error: "Invalid SHA-256 hash" }, { status: 400 });
        }

        const threat = await prisma.threatHash.upsert({
            where: { hash },
            update: {
                confidence: Math.max(confidence || 0, 0),
                threatType: threatType || undefined,
                updatedAt: new Date()
            },
            create: {
                hash,
                source: source || 'extension-ml',
                confidence: confidence || 1.0,
                threatType: threatType || null,
            }
        });

        return NextResponse.json({ success: true, threat }, { status: 201 });
    } catch (e: any) {
        console.error("Vault submit error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}
