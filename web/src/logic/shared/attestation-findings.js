// What the attestation and assertion checks found, in words: the sentence, in
// English and 中文, for each code the server reports (server/app/webauthn/attestation
// and assertion_checks.py; tests/fixtures/attestation-finding-codes.json lists them
// for both sides), and
// a finding read as its code, its sentence and the reason the server put after
// ": ". A code this table does not know is shown as it was sent. DOM-free: the
// findings list shows this model.

/** @import { AttestationFindings } from './registration-findings.js' */

/** @typedef {{ en: string, zh: string }} FindingSentence */

// No sentence ends in a full stop: a reason follows it after ": ".
/** @type {Readonly<Record<string, FindingSentence>>} */
export const FINDING_SENTENCES = Object.freeze({
    registration_response_invalid: {
        en: 'The registration response is not a JSON object',
        zh: '注册响应不是 JSON 对象',
    },
    registration_parse_error: {
        en: 'The registration response could not be read',
        zh: '无法读取注册响应',
    },
    client_data_type_invalid: {
        en: 'The client data\'s type is not webauthn.create',
        zh: '客户端数据的类型不是 webauthn.create',
    },
    challenge_mismatch: {
        en: 'The client data\'s challenge is not the one this server issued',
        zh: '客户端数据中的挑战（challenge）不是本服务器签发的挑战',
    },
    origin_mismatch: {
        en: 'The client data\'s origin is not the origin this server expects',
        zh: '客户端数据中的来源（origin）不是本服务器预期的来源',
    },
    cross_origin_not_allowed: {
        en: 'The credential was created in a cross-origin frame, which this server does not accept',
        zh: '凭据是在跨源（cross-origin）框架中创建的，本服务器不接受',
    },
    rp_id_hash_mismatch: {
        en: 'The authenticator data\'s RP ID hash is not the hash of this RP ID',
        zh: '认证器数据中的 RP ID 哈希与本 RP ID 的哈希不符',
    },
    user_presence_missing: {
        en: 'The authenticator did not report the user present (UP flag not set)',
        zh: '认证器未报告用户在场（UP 标志未设置）',
    },
    user_verification_required_not_satisfied: {
        en: 'User verification was required, but the authenticator did not verify the user (UV flag not set)',
        zh: '请求要求用户验证，但认证器未验证用户（UV 标志未设置）',
    },
    attested_credential_data_missing: {
        en: 'The authenticator data holds no attested credential data (AT flag not set)',
        zh: '认证器数据中没有已证明的凭据数据（AT 标志未设置）',
    },
    backup_state_without_eligibility: {
        en: 'The authenticator data says the credential is backed up (BS) but not backup eligible (BE)',
        zh: '认证器数据表明凭据已备份（BS），但不具备备份资格（BE）',
    },
    backup_eligibility_changed: {
        en: 'The credential\'s backup eligibility (BE) is not what it was at registration',
        zh: '凭据的备份资格（BE）与注册时不同',
    },
    algorithm_not_allowed: {
        en: 'The credential\'s algorithm is not one the request offered (pubKeyCredParams)',
        zh: '凭据的算法不在请求提供的算法（pubKeyCredParams）之中',
    },
    cose_key_error: {
        en: 'The credential\'s public key (a COSE key) could not be read',
        zh: '无法读取凭据的公钥（COSE 密钥）',
    },
    cose_key_invalid: {
        en: 'The credential\'s public key cannot be used for its algorithm',
        zh: '凭据的公钥无法用于其算法',
    },
    rsa_modulus_too_short: {
        en: 'The credential\'s RSA key is shorter than 2048 bits',
        zh: '凭据的 RSA 密钥短于 2048 位',
    },
    unsupported_attestation: {
        en: 'This server does not verify this attestation format',
        zh: '本服务器不验证此证明格式',
    },
    attestation_invalid: {
        en: 'The attestation statement does not verify',
        zh: '证明声明（attestation statement）验证未通过',
    },
    attestation_error: {
        en: 'The attestation statement could not be verified',
        zh: '无法验证证明声明',
    },
    attestation_signature_invalid: {
        en: 'The attestation\'s signature is not valid',
        zh: '证明签名无效',
    },
    trust_path_missing: {
        en: 'The attestation carries no certificate chain (x5c), so no certificate vouches for its key',
        zh: '证明中没有证书链（x5c），因此没有证书为其密钥担保',
    },
    certificate_chain_invalid: {
        en: 'The attestation\'s certificate chain does not verify (a certificate is not signed by its issuer)',
        zh: '证明的证书链验证未通过（某个证书不是由其签发者签名的）',
    },
    certificate_chain_unreadable: {
        en: 'The attestation\'s certificate chain could not be checked',
        zh: '无法检查证明的证书链',
    },
    certificate_parse_error: {
        en: 'A certificate in the attestation\'s chain could not be read',
        zh: '无法读取证明证书链中的某个证书',
    },
    certificate_out_of_validity: {
        en: 'A certificate in the attestation\'s chain is outside its validity period',
        zh: '证明证书链中的某个证书不在有效期内',
    },
    metadata_not_available: {
        en: 'No FIDO metadata was available to check the authenticator against',
        zh: '没有可用于核查该认证器的 FIDO 元数据',
    },
    metadata_lookup_failed: {
        en: 'Looking up the authenticator\'s metadata failed',
        zh: '查找认证器的元数据时出错',
    },
    metadata_entry_missing: {
        en: 'The metadata has no entry for this authenticator',
        zh: '元数据中没有该认证器的条目',
    },
    metadata_entry_revoked: {
        en: 'FIDO\'s metadata has revoked this authenticator\'s entry',
        zh: 'FIDO 元数据已撤销该认证器的条目',
    },
    attestation_root_not_found: {
        en: 'The metadata names no root certificate that issued this attestation\'s chain',
        zh: '元数据中没有签发该证明证书链的根证书',
    },
    attestation_root_not_trusted: {
        en: 'None of this attestation\'s root certificates is one this server is set to trust',
        zh: '该证明的根证书均不在本服务器设定信任的根证书之列',
    },
    metadata_not_fido_trusted: {
        en: 'The root certificate comes from metadata you uploaded, not from FIDO\'s own',
        zh: '根证书来自您上传的元数据，而非 FIDO 官方元数据',
    },
    algorithm_not_in_metadata: {
        en: 'The credential\'s algorithm is not among those the authenticator\'s metadata lists',
        zh: '凭据的算法不在该认证器元数据所列的算法之中',
    },
    user_handle_mismatch: {
        en: 'The user handle the authenticator returned is not the one the credential was registered with',
        zh: '认证器返回的用户句柄（user handle）不是注册该凭据时的用户句柄',
    },
    metadata_status_unsafe: {
        en: 'FIDO\'s metadata says this authenticator is not to be trusted',
        zh: 'FIDO 元数据表明不应信任该认证器',
    },
});

const SEVERITY_LABELS = { error: 'Error', warning: 'Warning' };

/** @typedef {'error' | 'warning'} FindingSeverity */

/**
 * One finding as the list shows it: its severity and that severity's word, its
 * code (the text before the first ":"), whether the table knows it, and what it
 * says in each language.
 * @typedef {{ severity: FindingSeverity, label: string, code: string, known: boolean, en: string, zh: string }} FindingView
 */

/**
 * A finding the server reported: a known code by its sentence, followed by the
 * reason the server put after ": " (the exception's message, a certificate's
 * subject); anything else as it was sent, in both languages.
 * @param {string} finding
 * @param {FindingSeverity} severity
 * @returns {FindingView}
 */
export function describeFinding(finding, severity) {
    const text = finding.trim();
    const colon = text.indexOf(':');
    const code = colon < 0 ? text : text.slice(0, colon);
    const label = SEVERITY_LABELS[severity];
    if (!Object.hasOwn(FINDING_SENTENCES, code)) {
        return { severity, label, code, known: false, en: text, zh: text };
    }
    const reason = colon < 0 ? '' : text.slice(colon + 1).trim();
    const { en, zh } = FINDING_SENTENCES[code];
    return reason
        ? { severity, label, code, known: true, en: `${en}: ${reason}`, zh: `${zh}: ${reason}` }
        : { severity, label, code, known: true, en, zh };
}

/**
 * Every finding, the errors first, each kind in the order the server gave.
 * @param {AttestationFindings} findings
 * @returns {FindingView[]}
 */
export function describeFindings({ errors, warnings }) {
    return [
        ...errors.map(finding => describeFinding(finding, 'error')),
        ...warnings.map(finding => describeFinding(finding, 'warning')),
    ];
}
