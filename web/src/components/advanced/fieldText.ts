// The registration form's own words, as the current templates give them
// (frontend/templates/advanced/tab/registration/*.html): each field's label,
// placeholder, options, the title of the button in it, its error, and its info
// popup in English and 中文 (a paragraph each). The labels of the byte fields
// carry " (hex)", as the current form writes them once the page has loaded.
// The logic's words come from the modules web/ imports.

export type FieldAbout = { en: string[]; zh: string[] };
export type FieldText = {
  label: string;
  placeholder?: string;
  options?: { value: string; label: string }[];
  button?: string;
  error?: string;
  about?: FieldAbout;
};

export const REGISTRATION_SECTIONS = ['User Identity', 'Authenticator Selection', 'Other Options', 'Extensions'] as const;

export const REGISTRATION_FIELDS = {
  // User Identity
  userId: {
    label: 'User ID (hex)',
    placeholder: 'Auto-generated hex value',
    button: 'Generate a new random User ID and username',
    error: 'Invalid hex value (1-64 bytes required)',
  },
  userName: {
    label: 'User Name',
    placeholder: 'Enter username',
  },
  displayName: {
    label: 'Display Name',
    placeholder: 'Auto-generated from username',
  },
  // Authenticator Selection
  attachment: {
    label: 'Authenticator Attachment',
    options: [{ value: 'cross-platform', label: 'Cross-Platform (default)' }, { value: 'platform', label: 'Platform' }, { value: 'unspecified', label: 'Unspecified' }],
    about: {
      en: ['Select whether an authenticator integrated into the client platform ("platform") or an external device ("cross-platform") should be used. If unspecified, either kind of authenticator is allowed. By default, a cross-platform authenticator is requested.'],
      zh: ['选择是否使用集成在客户端平台中的认证器（“platform”）或外部设备（“cross-platform”）。如果未指定，允许使用任一类型的认证器。默认情况下，将请求 cross-platform 认证器。'],
    },
  },
  residentKey: {
    label: 'Resident Key',
    options: [{ value: 'discouraged', label: 'Discouraged (default)' }, { value: 'preferred', label: 'Preferred' }, { value: 'required', label: 'Required' }],
    about: {
      en: ['A resident key can be used for "username-less" authentication, i.e., with an empty allowCredentials parameter.', 'If "discouraged", a non-resident key will be created if possible. If "preferred", a resident key will be created if possible. If "required", a resident key will be created and the user is shown an error if this fails. If unspecified, the default is "discouraged".'],
      zh: ['常驻密钥可用于“无用户名”身份验证，即使用空的 allowCredentials 参数。', '如果设为"discouraged"，在可能的情况下将创建非常驻密钥。如果设为"preferred"，在可能的情况下将创建常驻密钥。如果设为"required"，将创建常驻密钥，失败时向用户显示错误。如果未指定（选择unspecified），将默认为"discouraged"。'],
    },
  },
  userVerification: {
    label: 'User Verification',
    options: [{ value: 'preferred', label: 'Preferred (default)' }, { value: 'discouraged', label: 'Discouraged' }, { value: 'required', label: 'Required' }],
    about: {
      en: ['Select whether user verification (UV), for example a PIN or biometric, should be used.', 'If "discouraged", UV will not be used if possible. If "preferred", UV will be used if possible. If "required", UV will be used and the user is shown an error if this fails. If no preference is set, the default is "preferred".'],
      zh: ['选择是否应使用用户验证（UV），例如 PIN 或生物识别。', '如果设为"discouraged"，在可能的情况下不会使用 UV。如果设为"preferred"，在可能的情况下会使用 UV。如果设为"required"，会使用 UV，失败时向用户显示错误。如果未设置偏好，默认值为"preferred"。'],
    },
  },
  attestation: {
    label: 'Attestation',
    options: [{ value: 'direct', label: 'Direct (default)' }, { value: 'none', label: 'None' }, { value: 'indirect', label: 'Indirect' }, { value: 'enterprise', label: 'Enterprise' }],
    about: {
      en: ['Select whether the Relying Party (RP) requires authenticator attestation. Attestation is a way to prove what kind of authenticator is used.', 'If "none", no authenticator attestation will be returned. If "indirect", some kind of attestation will be returned if possible, but it may be anonymized by an attestation proxy. If "direct", the authenticator\'s original attestation will be returned, if any. If "enterprise", the authenticator is requested to produce an individually identifying attestation. By default, "direct" is used.'],
      zh: ['选择依赖方（RP）是否需要认证器证明。证明是一种证明使用何种认证器的方式。', '如果选择"none"，将不返回认证器证明。如果选择"indirect"，在可能的情况下会返回某种证明，但可能被证明代理匿名化。如果选择"direct"，将返回认证器的原始证明（如果有）。如果选择"enterprise"，请求认证器产生个别标识证明。默认情况下，使用"direct"。'],
    },
  },
  excludeCredentials: {
    label: 'Exclude Credentials',
    about: {
      en: ['Whether to include an excludeCredentials argument. This is used to prevent creating multiple credentials for the same account by excluding already registered credentials during registration.'],
      zh: ['是否包含 excludeCredentials 参数。这用于在注册过程中排除已注册的凭据，防止为同一账户创建多个凭据。'],
    },
  },
  fakeCredLength: {
    label: 'Fake credential ID length',
    button: 'Generate fake credential ID',
    about: {
      en: ['Add a random credential ID of the given length to excludeCredentials. May be useful for testing edge cases and conformance.'],
      zh: ['向 excludeCredentials 添加指定长度的随机凭据 ID。可能对测试个别情况和一致性有用。'],
    },
  },
  // Other Options
  challenge: {
    label: 'Challenge (hex)',
    placeholder: 'Auto-generated hex value',
    button: 'Generate new random challenge',
    error: 'Invalid hex value (minimum 16 bytes required)',
    about: {
      en: ['The cryptographic challenge to be signed by the authenticator, used to prevent replay attacks.'],
      zh: ['由认证器签名的加密挑战值，用于防止重放攻击。'],
    },
  },
  timeout: {
    label: 'Timeout (milliseconds)',
    about: {
      en: ['How long the Relying Party (RP) is willing to wait for the registration ceremony to complete. If the registration ceremony takes longer than this (or the adjusted value, in case the client overrides it), the ceremony will be aborted with a timeout message shown to the user. This may be silently overridden by the client.'],
      zh: ['依赖方（RP）等待注册完成的时间。如果注册仪式超过此时间，注册将被中止并向用户显示超时消息。客户端可能会覆盖此设置。'],
    },
  },
  algorithms: {
    label: 'Public Key Credential Parameters',
    about: {
      en: ['The signature algorithms supported by the Relying Party (RP). The authenticator will be choosing the most preferred algorithm that it supports. It is recommended to include at least ES256, EdDSA and RS256.'],
      zh: ['依赖方（RP）支持的签名算法。认证器将选择它支持的最优先算法。建议至少包括 ES256、EdDSA 和 RS256。'],
    },
  },
  hints: {
    label: 'Hints',
    options: [{ value: 'client-device', label: 'Client-device' }, { value: 'hybrid', label: 'Hybrid' }, { value: 'security-key', label: 'Security-key' }],
    about: {
      en: ['Registration hints to guide the user-agent in interacting with the user.', 'These hints are not requirements, and do not bind the user-agent, but may guide it in providing the best experience by using contextual information that the Relying Party has about the request. Hints are provided in order of decreasing preference so, if two hints are contradictory, the first one controls. Hints may also overlap: if a more-specific hint is defined a Relying Party may still wish to send less specific ones for user-agents that may not recognise the more specific one. In this case the most specific hint should be sent before the less-specific ones.', 'Hints MAY contradict information contained in credential transports and authenticatorAttachment. When this occurs, the hints take precedence.'],
      zh: ['注册提示用于指导用户代理与用户交互。', '这些提示不是强制要求，也不约束用户代理，但可利用依赖方掌握的上下文信息，引导其提供最佳体验。提示按优先级从高到低排列，因此若两个提示相互矛盾，则以前面的提示为准。提示也可以有重叠：如果定义了更具体的提示，依赖方仍可同时发送不那么具体的提示，以便那些可能无法识别更具体提示的用户代理使用。在这种情况下，应先发送最具体的提示，再发送较不具体的提示。', '提示可以与凭据传输方式和 authenticatorAttachment 中的信息相矛盾。如发生矛盾，应以提示为准。'],
    },
  },
  // Extensions
  credProps: {
    label: 'credProps',
    about: {
      en: ['Request the Credential Properties (credProps) extension. This extension may report properties such as whether a discoverable or non-discoverable credential was created.'],
      zh: ['请求凭据属性（credProps）扩展。此扩展可能报告属性，例如是否创建了可发现或不可发现的凭据。'],
    },
  },
  minPinLength: {
    label: 'minPinLength',
    about: {
      en: ['Request the Minimum PIN Length Extension (minPinLength). This extension may report the authenticator\'s currently configured minimum PIN length if the Relying Party (RP) is authorized to receive this value.'],
      zh: ['请求最小 PIN 长度扩展（minPinLength）。如果依赖方（RP）被授权接收此值，此扩展可能报告认证器当前配置的最小 PIN 长度。'],
    },
  },
  credProtect: {
    label: 'credProtect',
    options: [{ value: '', label: 'Unspecified (default)' }, { value: 'userVerificationOptional', label: 'userVerificationOptional' }, { value: 'userVerificationOptionalWithCredentialIDList', label: 'userVerificationOptionalWithCredentialIDList' }, { value: 'userVerificationRequired', label: 'userVerificationRequired' }],
    about: {
      en: ['Request the Credential protection (credProtect) extension. This extension sets whether the authenticator requires user verification (UV) before revealing the existence of a credential. If it does, that also means that the authenticator requires UV before allowing authentication using that credential.'],
      zh: ['请求凭据保护（credProtect）扩展。此扩展设置认证器在显示凭据存在之前是否需要用户验证（UV）。如果需要，这也意味着认证器在允许使用该凭据进行身份验证之前需要 UV。'],
    },
  },
  enforceCredProtect: {
    label: 'Enforce credProtect',
    about: {
      en: ['Whether to enforce the selected credProtect policy, if any, meaning the registration should fail rather than create a credential that does not satisfy the credProtect policy.', 'If this is checked and credProtect is set to userVerificationOptionalWithCredentialIDList or userVerificationRequired, and the authenticator cannot satisfy that policy, then the registration will fail. If this is not checked, the registration MAY proceed even if the authenticator cannot satisfy the chosen policy.'],
      zh: ['是否强制执行所选的 credProtect 策略（如果有），意味着注册应该失败而不是创建不满足 credProtect 策略的凭据。', '如果选中此项且 credProtect 设置为 userVerificationOptionalWithCredentialIDList 或 userVerificationRequired，并且认证器无法满足该策略，则注册将失败。如果未选中，即使认证器无法满足所选策略，注册也可能继续。'],
    },
  },
  largeBlob: {
    label: 'largeBlob',
    options: [{ value: '', label: 'Unspecified (default)' }, { value: 'preferred', label: 'Preferred' }, { value: 'required', label: 'Required' }],
    about: {
      en: ['Request the Large blob storage (largeBlob) extension. This extension may be used to store arbitrary data with the credential.', 'If the authenticator supports the extension, an extension output of largeBlob: { supported: true } will be returned. Use the largeBlob extension during an authentication ceremony to read or write the BLOB value.'],
      zh: ['请求Large blob 存储（largeBlob）扩展。此扩展可用于在凭据中存储任意数据。', '如果认证器支持此扩展，将返回 largeBlob: { supported: true } 的扩展输出。在身份验证仪式期间使用 largeBlob 扩展来读取或写入 BLOB 值。'],
    },
  },
  prf: {
    label: 'prf',
    about: {
      en: ['Request the Pseudo-random function (prf) extension. This extension may be used to derive deterministically-random values to use as key material, for example.', 'With CTAP authenticators, this requires that the authenticator supports the hmac-secret extension.', 'Many authenticators support evaluating the PRF only in authentication ceremonies, in which case the PRF extension output is just prf: { enabled: true } without any PRF outputs. To evaluate the PRF, perform an authentication ceremony with the same PRF inputs.'],
      zh: ['请求伪随机函数（prf）扩展。例如，此扩展可用于派生确定性随机值作为密钥材料。', '对于 CTAP 认证器，这要求认证器支持 hmac-secret 扩展。', '许多认证器仅支持在身份验证仪式中评估 PRF，在这种情况下，PRF 扩展输出只是 prf: { enabled: true }，没有任何 PRF 输出。要评估 PRF，请使用相同的 PRF 输入执行身份验证仪式。'],
    },
  },
  prfFirst: {
    label: 'prf eval first (hex)',
    placeholder: 'Hex value',
    button: 'Generate random PRF evaluation data',
    error: 'Invalid hex value (exactly 32 bytes required)',
    about: {
      en: ['The first prf extension input to evaluate. If set, the client extension outputs will include a prf.results.first output if the client and authenticator both support the extension.', 'Many authenticators support evaluating the PRF only in authentication ceremonies, in which case the PRF extension output is just prf: { enabled: true } without any PRF outputs. To evaluate the PRF, perform an authentication ceremony with the same PRF inputs.'],
      zh: ['要评估的第一个 prf 扩展输入。如果设置，如果客户端和认证器都支持该扩展，客户端扩展输出将包含 prf.results.first 输出。', '许多认证器仅支持在身份验证仪式中评估 PRF，在这种情况下，PRF 扩展输出只是 prf: { enabled: true }，没有任何 PRF 输出。要评估 PRF，请使用相同的 PRF 输入执行身份验证仪式。'],
    },
  },
  prfSecond: {
    label: 'prf eval second (hex)',
    placeholder: 'Hex value',
    button: 'Generate random PRF evaluation data',
    error: 'Invalid hex value (exactly 32 bytes required)',
    about: {
      en: ['The second prf extension input to evaluate. If set, the client extension outputs will include a prf.results.second output if the client and authenticator both support the extension.', 'This is optional and can be used alongside the first PRF evaluation input for additional key derivation capabilities.'],
      zh: ['要评估的第二个 prf 扩展输入。如果设置，如果客户端和认证器都支持该扩展，客户端扩展输出将包含 prf.results.second 输出。', '这是可选的，可以与第一个 PRF 评估输入一起使用，以获得额外的密钥派生功能。'],
    },
  },
} satisfies Record<string, FieldText>;
