-- CreateTable
CREATE TABLE "KnotWebhookEvent" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "eventKey" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "externalUserId" TEXT,
    "sessionId" TEXT,
    "taskId" INTEGER,
    "merchantId" INTEGER,
    "merchantName" TEXT,
    "timestampMs" BIGINT,
    "payloadJson" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "DiscountGrant" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "externalUserId" TEXT NOT NULL,
    "merchantId" INTEGER,
    "merchantName" TEXT,
    "discountCode" TEXT NOT NULL,
    "eventKey" TEXT,
    "issuedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "redeemedAt" DATETIME
);

-- CreateIndex
CREATE UNIQUE INDEX "KnotWebhookEvent_eventKey_key" ON "KnotWebhookEvent"("eventKey");

-- CreateIndex
CREATE UNIQUE INDEX "DiscountGrant_externalUserId_merchantId_key" ON "DiscountGrant"("externalUserId", "merchantId");

-- CreateIndex
CREATE INDEX "DiscountGrant_externalUserId_issuedAt_idx" ON "DiscountGrant"("externalUserId", "issuedAt");
