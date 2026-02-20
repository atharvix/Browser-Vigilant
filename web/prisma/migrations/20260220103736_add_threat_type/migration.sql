-- CreateTable
CREATE TABLE "ThreatHash" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "hash" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "confidence" REAL NOT NULL,
    "threatType" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "SyncLog" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "clientId" TEXT NOT NULL,
    "syncedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "hashCount" INTEGER NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "ThreatHash_hash_key" ON "ThreatHash"("hash");
