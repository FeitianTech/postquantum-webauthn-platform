import {describeCoseAlgorithm} from '../ui/display-utils.js';
import {
    describeCredentialAlgorithmTagWith,
    describeCredentialAlgorithmWith,
    resolveCredentialAlgorithmIdentifier,
} from '../credentials/algorithm-tag.js';

// The current UI's names for a credential's algorithm: ../credentials/algorithm-tag.js
// with display-utils' describer.

export { resolveCredentialAlgorithmIdentifier };

export function describeCredentialAlgorithm(credential) {
    return describeCredentialAlgorithmWith(credential, describeCoseAlgorithm);
}

export function describeCredentialAlgorithmTag(credential) {
    return describeCredentialAlgorithmTagWith(credential, describeCoseAlgorithm);
}
