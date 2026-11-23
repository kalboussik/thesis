'use strict';

/**
 * loadModel.js
 * -------------------------------------------------------------------------
 * Central place that maps the IoT-IDS deployment scenario to a blockchain
 * transaction load, so the thesis can state the assumptions transparently
 * (mirroring Marwa's "3N tx/s" derivation for V2X).
 *
 * Model (document these assumptions in the chapter):
 *   - Monitoring window  W = 30 s (matches the profiling window in Ch. 6).
 *   - During an attack episode, a fraction p_attack of the N monitored nodes
 *     produce one confirmed alert per window.
 *   - Each confirmed alert => 1 submitAlert + 1 validateAlert + (occasionally)
 *     1 updateReputation transaction.
 *   - Agent registration/migration is comparatively rare (handled in its own
 *     round), so steady-state load is dominated by alert traffic.
 *
 * The benchmark sweeps N (network size) over {10, 25, 50, 75, 100} to match
 * the scalability points already used in the simulation chapter.
 */

const WINDOW_SECONDS = 30;

// fraction of nodes generating confirmed alerts during a peak attack episode
const P_ATTACK = 0.20;

// the four real attack classes (deauth/MITM removed — not visible at the router)
const ATTACK_CLASSES = ['dos', 'ddos', 'portscan', 'bruteforce'];
const SEVERITIES = ['low', 'medium', 'high'];

/**
 * Offered alert transactions per second for a network of N nodes at peak.
 * e.g. N=100 -> 100*0.20/30 ≈ 0.67 alert tx/s steady-state.
 * Caliper drives a configurable multiple of this so you can characterise the
 * ledger well beyond the nominal operating point.
 */
function alertTpsForNetwork(N) {
    return (N * P_ATTACK) / WINDOW_SECONDS;
}

function randomFrom(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

module.exports = {
    WINDOW_SECONDS,
    P_ATTACK,
    ATTACK_CLASSES,
    SEVERITIES,
    alertTpsForNetwork,
    randomFrom,
};
