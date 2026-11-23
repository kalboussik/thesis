'use strict';
const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const crypto = require('crypto');

class QueryHistoryWorkload extends WorkloadModuleBase {
    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.contractId = roundArguments.contractId;
        this.agentID = `histagent_w${this.workerIndex}`;
        const pk = crypto.createHash('sha256').update(this.agentID).digest('hex');
        await this.sutAdapter.sendRequests({
            contractId: this.contractId, contractFunction: 'registerAgent',
            invokerIdentity: 'User1', contractArguments: [this.agentID, 'gw_1', pk, 'region_1'], readOnly: false,
        });
        for (let i = 0; i < 20; i++) {
            const h = crypto.createHash('sha256').update(`${this.agentID}_${i}`).digest('hex');
            await this.sutAdapter.sendRequests({
                contractId: this.contractId, contractFunction: 'submitAlert',
                invokerIdentity: 'User1', contractArguments: [`h_${this.agentID}_${i}`, this.agentID, h, 'portscan', 'medium'], readOnly: false,
            });
        }
    }
    async submitTransaction() {
        await this.sutAdapter.sendRequests({
            contractId: this.contractId,
            contractFunction: 'queryHistory',
            invokerIdentity: 'User1',
            contractArguments: [this.agentID],
            readOnly: true,
        });
    }
}
function createWorkloadModule() { return new QueryHistoryWorkload(); }
module.exports.createWorkloadModule = createWorkloadModule;
