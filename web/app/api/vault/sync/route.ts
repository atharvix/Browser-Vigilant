// @ts-nocheck
import { NextResponse } from 'next/server';

// In-memory blockchain threat registry
const threatRegistry = new Map<string, any>();
const syncLogs = new Map<string, any>();

export async function GET(req: Request) {
    try {
        const { searchParams } = new URL(req.url);
        const since = searchParams.get('since');
        const clientId = searchParams.get('clientId') || 'anonymous';

        // Get all verified threats from blockchain registry
        const allThreats = Array.from(threatRegistry.values());
        const verifiedThreats = allThreats.filter(t => t.status === 'verified' || t.confidence > 0.8);
        
        // Filter by timestamp if provided
        let recentThreats = verifiedThreats;
        if (since) {
            const sinceTimestamp = parseInt(since, 10);
            if (!isNaN(sinceTimestamp)) {
                recentThreats = verifiedThreats.filter(t => 
                    new Date(t.updatedAt).getTime() > sinceTimestamp
                );
            }
        }

        const hashes = recentThreats.map(t => t.hash);

        // Record sync event
        const syncId = `sync_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        syncLogs.set(syncId, {
            id: syncId,
            clientId,
            syncedAt: new Date().toISOString(),
            hashCount: hashes.length,
            threatHashes: hashes
        });

        return NextResponse.json({
            success: true,
            count: hashes.length,
            hashes: hashes,
            timestamp: Date.now(),
            syncId: syncId
        }, { status: 200 });

    } catch (e: any) {
        console.error("Blockchain vault sync error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}

// POST for submitting multiple threats at once
export async function POST(req: Request) {
    try {
        const body = await req.json();
        const { threats, clientId } = body;

        if (!Array.isArray(threats)) {
            return NextResponse.json({ error: "Threats must be an array" }, { status: 400 });
        }

        const results = [];
        for (const threat of threats) {
            const { hash, source, confidence, threatType } = threat;
            
            if (hash && typeof hash === 'string' && hash.length === 64) {
                const existingThreat = threatRegistry.get(hash);
                
                if (existingThreat) {
                    existingThreat.confidence = Math.max(confidence || 0, existingThreat.confidence);
                    existingThreat.threatType = threatType || existingThreat.threatType;
                    existingThreat.updatedAt = new Date().toISOString();
                    existingThreat.sources = [...new Set([...(existingThreat.sources || []), source || 'extension'])];
                } else {
                    threatRegistry.set(hash, {
                        hash,
                        source: source || 'extension-ml',
                        confidence: confidence || 1.0,
                        threatType: threatType || null,
                        sources: [source || 'extension'],
                        createdAt: new Date().toISOString(),
                        updatedAt: new Date().toISOString(),
                        status: 'pending'
                    });
                }
                results.push({ hash, success: true });
            }
        }

        return NextResponse.json({
            success: true,
            processed: results.length,
            results: results
        }, { status: 200 });

    } catch (e: any) {
        console.error("Bulk threat submission error:", e);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}
