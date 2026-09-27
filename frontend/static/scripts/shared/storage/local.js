// The current UI's barrel for the saved credentials: ./records.js, seeded from
// the page's "initial-credential-records" block, which the server never renders
// and the tests give (tests/frontend/setup.js).
import { readPageData } from '../utils/page-data.js';
import { seedUnifiedCredentialRecords } from './local/storage-core.js';

seedUnifiedCredentialRecords(readPageData('initial-credential-records'));

export * from './records.js';

export default {

};
