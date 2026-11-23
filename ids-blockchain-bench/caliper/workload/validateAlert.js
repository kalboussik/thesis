'use strict';
const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const crypto = require('crypto');

class ValidateAlertWorkload extends WorkloadModuleBase {
    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.contractId = roundArguments.contractId;
        this.prepared = roundArguments.prepared || 200;
        this.counter = 0;
        this.hashes = {};

        const agentID = `valagent_w${this.workerIndex}`;
        const pk = crypto.createHash('sha256').update(agentID).digest('hex');
        await this.sutAdapter.sendRequests({
            contractId: this.contractId, contractFunction: 'registerAgent',
            invokerIdentity: 'User1', contractArguments: [agentID, 'gw_0', pk, 'region_0'], readOnly: false,
        });
        for (let i = 0; i < this.prepared; i++) {
            const alertID = `valalert_w${this.workerIndex}_${i}`;
            const payload = JSON.stringify({ alertID, i });
            const h = crypto.createHash('sha256').update(payload).digest('hex');
            this.hashes[alertID] = h;
            await this.sutAdapter.sendRequests({
                contractId: this.contractId, contractFunction: 'submitAlert',
                invokerIdentity: 'User1', contractArguments: [alertID, agentID, h, 'dos', 'high'], readOnly: false,
            });
        }
    }
    async submitTransaction() {
        const i = this.counter++ % this.prepared;
        const alertID = `valalert_w${this.workerIndex}_${i}`;
        await this.sutAdapter.sendRequests({
            contractId: this.contractId,
            contractFunction: 'validateAlert',
            invokerIdentity: 'User1',
            contractArguments: [alertID, this.hashes[alertID]],
            readOnly: false,
        });
    }
}
function createWorkloadModule() { return new ValidateAlertWorkload(); }
module.exports.createWorkloadModule = createWorkloadModule;
