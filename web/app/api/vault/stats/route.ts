// @ts-nocheck
import { NextResponse } from 'next/server';

// In-memory blockchain threat registry
const threatRegistry = new Map<string, any>();
const syncLogs = new Map<string, any>();

export async function GET() {
    try {
        // Get all threats from blockchain registry
        const allThreats = Array.from(threatRegistry.values());
        const verifiedThreats = allThreats.filter(t => t.status === 'verified' || t.confidence > 0.8);
        const pendingThreats = allThreats.filter(t => t.status === 'pending');
        const rejectedThreats = allThreats.filter(t => t.status === 'rejected');
        
        // Get recent threats (last 10)
        const recentThreats = allThreats
            .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
            .slice(0, 10)
            .map(t => ({
                hash: t.hash,
                source: t.source,
                confidence: t.confidence,
                createdAt: t.createdAt,
                status: t.status
            }));
        
        // Source breakdown
        const sourceMap = new Map<string, number>();
        allThreats.forEach(threat => {
            const source = threat.source || 'unknown';
            sourceMap.set(source, (sourceMap.get(source) || 0) + 1);
        });
        
        const sourceBreakdown = Array.from(sourceMap.entries())
            .map(([source, count]) => ({ source, count }))
            .sort((a, b) => b.count - a.count);
        
        // Sync logs count
        const totalSyncs = syncLogs.size;

        return NextResponse.json({
            totalThreats: allThreats.length,
            verifiedThreats: verifiedThreats.length,
            pendingThreats: pendingThreats.length,
            rejectedThreats: rejectedThreats.length,
            recentThreats,
            totalSyncs,
            sourceBreakdown,
            blockchainStats: {
                registrySize: threatRegistry.size,
                syncLogSize: syncLogs.size,
                verifiedRatio: allThreats.length > 0 ? (verifiedThreats.length / allThreats.length).toFixed(3) : 0
            }
        });
    } catch (e: any) {
        console.error('Blockchain vault stats error:', e);
        return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
    }
}
