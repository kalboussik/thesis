'use strict';
const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const crypto = require('crypto');
const { randomFrom } = require('./loadModel');

class RegisterAgentWorkload extends WorkloadModuleBase {
    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.contractId = roundArguments.contractId;
        this.territories = roundArguments.territories || 8;
        this.counter = 0;
    }
    async submitTransaction() {
        const id = `agent_w${this.workerIndex}_${this.counter++}`;
        const gateway = `gw_${Math.floor(Math.random() * this.territories)}`;
        const pubKeyHash = crypto.createHash('sha256').update(id).digest('hex');
        const territory = `region_${Math.floor(Math.random() * this.territories)}`;
        await this.sutAdapter.sendRequests({
            contractId: this.contractId,
            contractFunction: 'registerAgent',
            invokerIdentity: 'User1',
            contractArguments: [id, gateway, pubKeyHash, territory],
            readOnly: false,
        });
    }
}
function createWorkloadModule() { return new RegisterAgentWorkload(); }
module.exports.createWorkloadModule = createWorkloadModule;
