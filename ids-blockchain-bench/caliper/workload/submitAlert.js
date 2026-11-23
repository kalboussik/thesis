'use strict';
const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const crypto = require('crypto');
const { ATTACK_CLASSES, SEVERITIES, randomFrom } = require('./loadModel');

/**
 * Pre-seeds a pool of registered agents during init, then submits alerts
 * referencing those agents. Each alert anchors only a SHA-256 hash of a
 * synthetic off-chain payload (the real payload never touches the ledger).
 */
class SubmitAlertWorkload extends WorkloadModuleBase {
    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.contractId = roundArguments.contractId;
        this.agentPool = roundArguments.agentPool || 20;
        this.counter = 0;

        // seed agents this worker will reference
        for (let i = 0; i < this.agentPool; i++) {
            const id = `alagent_w${this.workerIndex}_${i}`;
            const pk = crypto.createHash('sha256').update(id).digest('hex');
            await this.sutAdapter.sendRequests({
                contractId: this.contractId,
                contractFunction: 'registerAgent',
                invokerIdentity: 'User1',
                contractArguments: [id, `gw_${i % 8}`, pk, `region_${i % 8}`],
                readOnly: false,
            });
        }
    }
    async submitTransaction() {
        const agentIdx = Math.floor(Math.random() * this.agentPool);
        const agentID = `alagent_w${this.workerIndex}_${agentIdx}`;
        const alertID = `alert_w${this.workerIndex}_${this.counter++}`;
        // synthetic off-chain payload -> integrity hash (132-byte-class metadata, like Marwa)
        const payload = JSON.stringify({ alertID, ts: Date.now(), window: 30 });
        const alertHash = crypto.createHash('sha256').update(payload).digest('hex');
        await this.sutAdapter.sendRequests({
            contractId: this.contractId,
            contractFunction: 'submitAlert',
            invokerIdentity: 'User1',
            contractArguments: [alertID, agentID, alertHash, randomFrom(ATTACK_CLASSES), randomFrom(SEVERITIES)],
            readOnly: false,
        });
    }
}
function createWorkloadModule() { return new SubmitAlertWorkload(); }
module.exports.createWorkloadModule = createWorkloadModule;
