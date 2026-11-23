'use strict';

const { Contract } = require('fabric-contract-api');

/**
 * IDSLedger
 * -------------------------------------------------------------------------
 * Permissioned-blockchain coordination layer for the distributed multi-agent
 * IoT IDS (thesis Chapter 6). The ledger stores ONLY lightweight coordination
 * metadata and integrity markers (hashes) — never raw traffic, full alerts,
 * or feature datasets. Those remain off-chain.
 *
 * Five smart-contract functions:
 *   1. registerAgent     — register/migrate a Mobile Detection Agent (MDA)
 *   2. submitAlert        — record alert metadata + integrity hash (off-chain payload)
 *   3. validateAlert      — verify alert came from an authorized agent + hash integrity
 *   4. updateReputation   — adjust an agent's trust score
 *   5. queryHistory       — retrieve an agent's registration/migration/alert history
 *
 * IMPORTANT (Fabric determinism): timestamps come from the transaction
 * proposal (ctx.stub.getTxTimestamp), NOT Date.now(), so all endorsers
 * compute identical write-sets.
 */
class IDSLedger extends Contract {

    // ---- helpers ---------------------------------------------------------

    _txTime(ctx) {
        const ts = ctx.stub.getTxTimestamp();
        // seconds.nanos -> ISO-ish epoch ms (deterministic)
        return Math.floor(ts.seconds.low * 1000 + ts.nanos / 1e6);
    }

    async _readState(ctx, key) {
        const data = await ctx.stub.getState(key);
        if (!data || data.length === 0) return null;
        return JSON.parse(data.toString());
    }

    // ---- 1. agent registration / migration -------------------------------

    /**
     * Register a new MDA, or record a migration if it already exists.
     * @param {String} agentID      cryptographic agent identifier
     * @param {String} gatewayID    gateway/edge node currently hosting the agent
     * @param {String} pubKeyHash   hash of the agent's public key
     * @param {String} territory    monitored region the agent is authorized for
     */
    async registerAgent(ctx, agentID, gatewayID, pubKeyHash, territory) {
        if (!agentID || !gatewayID) {
            throw new Error('agentID and gatewayID are required');
        }
        const key = ctx.stub.createCompositeKey('agent', [agentID]);
        const existing = await this._readState(ctx, key);
        const now = this._txTime(ctx);

        let record;
        let eventName;
        if (existing) {
            // migration: same identity, new gateway/territory
            record = existing;
            record.previousGateway = existing.gatewayID;
            record.gatewayID = gatewayID;
            record.territory = territory;
            record.migrations = (existing.migrations || 0) + 1;
            record.lastUpdated = now;
            eventName = 'AgentMigrated';
        } else {
            record = {
                docType: 'agent',
                agentID,
                gatewayID,
                pubKeyHash,
                territory,
                reputation: 0,
                migrations: 0,
                registeredAt: now,
                lastUpdated: now,
            };
            eventName = 'AgentRegistered';
        }

        await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));

        // append an immutable history entry
        await this._appendHistory(ctx, agentID, {
            type: eventName,
            gatewayID,
            territory,
            ts: now,
        });

        ctx.stub.setEvent(eventName, Buffer.from(JSON.stringify({ agentID, gatewayID, ts: now })));
        return JSON.stringify(record);
    }

    // ---- 2. alert submission --------------------------------------------

    /**
     * Record alert metadata and an integrity marker. The full alert (traffic
     * window, features) is stored OFF-CHAIN; only the hash is anchored here.
     * @param {String} alertID
     * @param {String} agentID      submitting agent
     * @param {String} alertHash    SHA-256 of the off-chain alert payload
     * @param {String} attackClass  one of: dos | ddos | portscan | bruteforce
     * @param {String} severity     low | medium | high
     */
    async submitAlert(ctx, alertID, agentID, alertHash, attackClass, severity) {
        if (!alertID || !agentID || !alertHash) {
            throw new Error('alertID, agentID and alertHash are required');
        }
        const agentKey = ctx.stub.createCompositeKey('agent', [agentID]);
        const agent = await this._readState(ctx, agentKey);
        if (!agent) {
            throw new Error(`unauthorized: agent ${agentID} is not registered`);
        }

        const now = this._txTime(ctx);
        const key = ctx.stub.createCompositeKey('alert', [alertID]);
        const record = {
            docType: 'alert',
            alertID,
            agentID,
            territory: agent.territory,
            alertHash,
            attackClass,
            severity,
            validated: false,
            submittedAt: now,
        };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(record)));

        await this._appendHistory(ctx, agentID, {
            type: 'AlertSubmitted',
            alertID,
            attackClass,
            ts: now,
        });

        ctx.stub.setEvent('AlertSubmitted',
            Buffer.from(JSON.stringify({ alertID, agentID, attackClass, ts: now })));
        return JSON.stringify(record);
    }

    // ---- 3. alert validation (integrity + authorization) -----------------

    /**
     * Validate an alert: the submitting agent must be registered and authorized
     * for the alert's territory, and the provided hash must match the anchored
     * integrity marker.
     * @param {String} alertID
     * @param {String} providedHash  hash recomputed by the validator from the
     *                               off-chain payload
     */
    async validateAlert(ctx, alertID, providedHash) {
        const key = ctx.stub.createCompositeKey('alert', [alertID]);
        const alert = await this._readState(ctx, key);
        if (!alert) {
            throw new Error(`alert ${alertID} not found`);
        }
        const agentKey = ctx.stub.createCompositeKey('agent', [alert.agentID]);
        const agent = await this._readState(ctx, agentKey);

        const authorized = !!agent && agent.territory === alert.territory;
        const integrityOk = alert.alertHash === providedHash;
        const valid = authorized && integrityOk;

        alert.validated = valid;
        alert.validatedAt = this._txTime(ctx);
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(alert)));

        ctx.stub.setEvent('AlertValidated',
            Buffer.from(JSON.stringify({ alertID, valid, authorized, integrityOk })));
        return JSON.stringify({ alertID, valid, authorized, integrityOk });
    }

    // ---- 4. reputation update -------------------------------------------

    /**
     * Adjust an agent's trust score. Confirmed detections raise reputation;
     * unconfirmed/false ones penalize it.
     * @param {String} agentID
     * @param {String} confirmed  'true' | 'false'
     */
    async updateReputation(ctx, agentID, confirmed) {
        const key = ctx.stub.createCompositeKey('agent', [agentID]);
        const agent = await this._readState(ctx, key);
        if (!agent) {
            throw new Error(`agent ${agentID} not found`);
        }
        const delta = (confirmed === 'true' || confirmed === true) ? 1 : -2;
        agent.reputation += delta;
        agent.lastUpdated = this._txTime(ctx);
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(agent)));

        ctx.stub.setEvent('ReputationUpdated',
            Buffer.from(JSON.stringify({ agentID, reputation: agent.reputation })));
        return JSON.stringify({ agentID, reputation: agent.reputation });
    }

    // ---- 5. history query ------------------------------------------------

    async _appendHistory(ctx, agentID, entry) {
        // monotonic ordering via tx id keeps entries unique & deterministic
        const seq = ctx.stub.getTxID();
        const key = ctx.stub.createCompositeKey('history', [agentID, seq]);
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(entry)));
    }

    /**
     * Return the full coordination history (registrations, migrations, alerts)
     * for one agent. Read-only.
     */
    async queryHistory(ctx, agentID) {
        const iterator = await ctx.stub.getStateByPartialCompositeKey('history', [agentID]);
        const results = [];
        let res = await iterator.next();
        while (!res.done) {
            if (res.value && res.value.value) {
                results.push(JSON.parse(res.value.value.toString()));
            }
            res = await iterator.next();
        }
        await iterator.close();
        return JSON.stringify(results);
    }

    // ---- read helpers (used by tests / sanity checks) --------------------

    async readAgent(ctx, agentID) {
        const key = ctx.stub.createCompositeKey('agent', [agentID]);
        const agent = await this._readState(ctx, key);
        if (!agent) throw new Error(`agent ${agentID} not found`);
        return JSON.stringify(agent);
    }
}

module.exports = IDSLedger;
