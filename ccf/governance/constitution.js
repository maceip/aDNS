class Action {
  constructor(validate, apply) {
    this.validate = validate;
    this.apply = apply;
  }
}

function parseUrl(url) {
  // From https://tools.ietf.org/html/rfc3986#appendix-B
  const re = new RegExp(
    "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?",
  );
  const groups = url.match(re);
  if (!groups) {
    throw new TypeError(`${url} is not a valid URL.`);
  }
  return {
    scheme: groups[2],
    authority: groups[4],
    path: groups[5],
    query: groups[7],
    fragment: groups[9],
  };
}

function hexStrToBuf(hexStr) {
  const result = [];

  for (let i = 0; i < hexStr.length; i += 2) {
    const octet = hexStr.slice(i, i + 2);
    if (octet.length != 2) {
      throw new Error("Hex string invalid: length must be multiple of 2");
    }
    if (octet.match(/[G-Z\s]/i)) {
      throw new Error(`Hex string invalid: Non-hex character ${octet}`);
    }
    result.push(parseInt(octet, 16));
  }

  return new Uint8Array(result).buffer;
}

function checkType(value, type, field) {
  const optional = type.endsWith("?");
  if (optional) {
    if (value === null || value === undefined) {
      return;
    }
    type = type.slice(0, -1);
  }
  if (type === "array") {
    if (!Array.isArray(value)) {
      throw new Error(`${field} must be an array`);
    }
  } else if (type === "integer") {
    if (!Number.isInteger(value)) {
      throw new Error(`${field} must be an integer`);
    }
  } else if (typeof value !== type) {
    throw new Error(`${field} must be of type ${type} but is ${typeof value}`);
  }
}

function checkEnum(value, members, field) {
  if (!members.includes(value)) {
    throw new Error(`${field} must be one of ${members}`);
  }
}

function checkBounds(value, low, high, field) {
  if (low !== null && value < low) {
    throw new Error(`${field} must be greater than ${low}`);
  }
  if (high !== null && value > high) {
    throw new Error(`${field} must be lower than ${high}`);
  }
}

function checkArrayLength(value, min, max, field) {
  checkType(value, "array", field);
  if (min !== null && value.length < min) {
    throw new Error(`${field} must be an array of minimum ${min} elements`);
  }
  if (max !== null && value.length > max) {
    throw new Error(`${field} must be an array of maximum ${max} elements`);
  }
}

function checkArrayBufferLength(value, min, max, field) {
  if (min !== null && value.length < min) {
    throw new Error(`${field} must be an array of minimum ${min} elements`);
  }
  if (max !== null && value.length > max) {
    throw new Error(`${field} must be an array of maximum ${max} elements`);
  }
}

function checkBase64Url(value, field) {
  checkType(value, "string", field);
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error(`${field} must be base64url encoded`);
  }
}

function base64UrlByteLength(value, field) {
  checkBase64Url(value, field);
  return Math.floor(value.length / 4) * 3 + [0, 0, 1, 2][value.length % 4];
}

function splitX509CertBundle(value) {
  // Match complete PEM certificates with both BEGIN and END markers.
  // This ensures we only extract valid PEM blocks and reject malformed input.
  const pemPattern =
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const certs = value.match(pemPattern);

  if (!certs || certs.length === 0) {
    throw new Error("No valid PEM certificates found in bundle");
  }

  // Verify the input contains only certificates and whitespace.
  // Use a single-pass approach: replace all matched certificates with empty string
  // using the global regex, then check if only whitespace remains.
  const remaining = value.replace(pemPattern, "");

  if (remaining.trim() !== "") {
    throw new Error(
      "Certificate bundle contains invalid content between certificates",
    );
  }

  return certs;
}

function checkX509CACertBundle(value, field) {
  checkX509CertBundle(value, field);
  // isValidX509RootCACert(pem) is backed by a C++ function that checks both
  // X509_check_ca (CA:TRUE or self-signed x509v1) and EXFLAG_SS (self-signed).
  // Every certificate in the bundle must be a root (self-signed) CA; intermediate
  // CAs are rejected even when their signing root is also present in the bundle.
  for (const [i, cert] of splitX509CertBundle(value).entries()) {
    if (!ccf.crypto.isValidX509RootCACert(cert)) {
      throw new Error(
        `${field}[${i}] must be a self-signed (root) CA certificate`,
      );
    }
  }
}

function checkRsaPublicKey(jwk, field) {
  checkType(jwk.n, "string", `${field}.n`);
  checkType(jwk.e, "string", `${field}.e`);
  checkBase64Url(jwk.e, `${field}.e`);
  // RFC 7518 section 6.3.1.1 requires `n` to be the unsigned big-endian modulus with
  // no leading zero octets. Under that encoding a 2048-bit modulus is exactly
  // 256 octets, so anything shorter is conclusively below 2048 bits and the
  // key is too weak. Encoded length is a sufficient (and cheap) proxy here;
  // the precise bit length is not exposed to JS, but pubRsaJwkToPem below
  // catches any structurally-invalid modulus.
  if (base64UrlByteLength(jwk.n, `${field}.n`) < 256) {
    throw new Error(`${field}.n must be at least 2048 bits`);
  }
  try {
    ccf.crypto.pubRsaJwkToPem({
      kty: "RSA",
      kid: jwk.kid,
      n: jwk.n,
      e: jwk.e,
    });
  } catch (e) {
    throw new Error(`${field} must be a valid RSA public key`);
  }
}

function checkEcPublicKey(jwk, field) {
  checkType(jwk.x, "string", `${field}.x`);
  checkType(jwk.y, "string", `${field}.y`);
  checkType(jwk.crv, "string", `${field}.crv`);
  checkEnum(jwk.crv, ["P-256", "P-384", "P-521"], `${field}.crv`);
  const coordinateLengths = { "P-256": 32, "P-384": 48, "P-521": 66 };
  const coordinateLength = coordinateLengths[jwk.crv];
  if (base64UrlByteLength(jwk.x, `${field}.x`) !== coordinateLength) {
    throw new Error(`${field}.x must be ${coordinateLength} bytes`);
  }
  if (base64UrlByteLength(jwk.y, `${field}.y`) !== coordinateLength) {
    throw new Error(`${field}.y must be ${coordinateLength} bytes`);
  }
  try {
    ccf.crypto.pubJwkToPem({
      kty: "EC",
      kid: jwk.kid,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
    });
  } catch (e) {
    throw new Error(`${field} must be a valid EC public key`);
  }
}

const cpuid_length_bytes = 4;
function checkValidCpuid(value, field) {
  checkType(value, "string", field);
  if (value !== value.toLowerCase()) {
    throw new Error(`${field} must be a lowercase hex string: ${value}`);
  }

  // This will throw if the string contains non-hex characters
  const buffer = hexStrToBuf(value);
  const length = buffer.byteLength;
  if (length != cpuid_length_bytes) {
    throw new Error(
      `${field} must convert to exactly ${cpuid_length_bytes} bytes`,
    );
  }
}

const tcb_version_length_bytes = 8;
function checkValidTcbVersionHex(value, field) {
  checkType(value, "string", field);
  if (value !== value.toLowerCase()) {
    throw new Error(`${field} must be a lowercase hex string: ${value}`);
  }

  // This will throw if the string contains non-hex characters
  const buffer = hexStrToBuf(value);
  const length = buffer.byteLength;
  if (length != tcb_version_length_bytes) {
    throw new Error(
      `${field} must convert to exactly ${tcb_version_length_bytes} bytes`,
    );
  }
}

function checkNone(args) {
  if (args !== null && args !== undefined) {
    throw new Error(`Proposal does not accept any argument, found "${args}"`);
  }
}

function checkEntityId(value, field) {
  checkType(value, "string", field);
  // This should be the hex-encoding of a SHA256 digest. This is 32 bytes long, so
  // produces 64 hex characters.
  const digestLength = 64;
  if (value.length !== digestLength) {
    throw new Error(`${field} must contain exactly ${digestLength} characters`);
  }
  const re = new RegExp("^[a-fA-F0-9]*$");
  if (!re.test(value)) {
    throw new Error(`${field} contains non-hexadecimal character`);
  }
}

function getSingletonKvKey() {
  // When a KV map only contains one value, this is the key at which
  // the value is recorded
  return new ArrayBuffer(8);
}

function getActiveRecoveryMembersCount() {
  let activeRecoveryMembersCount = 0;
  ccf.kv["public:ccf.gov.members.encryption_public_keys"].forEach((_, k) => {
    let rawMemberInfo = ccf.kv["public:ccf.gov.members.info"].get(k);
    if (rawMemberInfo === undefined) {
      throw new Error(`Recovery member ${ccf.bufToStr(k)} has no information`);
    }

    const memberInfo = ccf.bufToJsonCompatible(rawMemberInfo);
    if (memberInfo.status === "Active") {
      activeRecoveryMembersCount++;
    }
  });
  return activeRecoveryMembersCount;
}

function getServiceStatus() {
  const rawService =
    ccf.kv["public:ccf.gov.service.info"].get(getSingletonKvKey());
  if (rawService === undefined) {
    throw new Error("Service information could not be found");
  }

  return ccf.bufToJsonCompatible(rawService).status;
}

function isServiceRecovering() {
  const serviceStatus = getServiceStatus();
  return (
    serviceStatus === "Recovering" ||
    serviceStatus === "WaitingForRecoveryShares"
  );
}

function checkRecoveryMemberChange(memberId, hasInputEncryptionKey) {
  if (!isServiceRecovering()) {
    return;
  }

  if (
    hasInputEncryptionKey ||
    ccf.kv["public:ccf.gov.members.encryption_public_keys"].has(memberId)
  ) {
    throw new Error("Cannot change recovery members during recovery");
  }
}

function checkRecoverySharesChange() {
  if (isServiceRecovering()) {
    throw new Error(
      "Cannot change the recovery threshold, refresh recovery shares, or rekey the ledger during recovery",
    );
  }
}

function checkJwks(value, field) {
  checkType(value, "object", field);
  checkType(value.keys, "array", `${field}.keys`);
  const kids = new Set();
  for (const [i, jwk] of value.keys.entries()) {
    const keyField = `${field}.keys[${i}]`;
    checkType(jwk.kid, "string", `${field}.keys[${i}].kid`);
    if (kids.has(jwk.kid)) {
      throw new Error(`${field}.keys[${i}].kid must be unique`);
    }
    kids.add(jwk.kid);
    checkType(jwk.kty, "string", `${field}.keys[${i}].kty`);
    checkEnum(jwk.kty, ["RSA", "EC"], `${field}.keys[${i}].kty`);
    if (jwk.use !== undefined) {
      checkType(jwk.use, "string", `${keyField}.use`);
      checkEnum(jwk.use, ["sig"], `${keyField}.use`);
    }
    if (jwk.alg !== undefined) {
      checkType(jwk.alg, "string", `${keyField}.alg`);
      let allowedAlg;
      if (jwk.kty === "RSA") {
        allowedAlg = ["RS256"];
      } else {
        // Per RFC 7518 section 3.4, EC alg is determined by the curve. When
        // only x5c is supplied, crv may not be present on the JWK; in that
        // case allow any of the supported ES* algorithms and rely on the cert
        // to bind alg to curve.
        const ecAlgByCrv = {
          "P-256": "ES256",
          "P-384": "ES384",
          "P-521": "ES512",
        };
        allowedAlg =
          jwk.crv && ecAlgByCrv[jwk.crv]
            ? [ecAlgByCrv[jwk.crv]]
            : Object.values(ecAlgByCrv);
      }
      checkEnum(jwk.alg, allowedAlg, `${keyField}.alg`);
    }
    if (jwk.x5c) {
      checkArrayLength(jwk.x5c, 1, null, `${field}.keys[${i}].x5c`);
      let certBundle = "";
      for (const [j, b64der] of jwk.x5c.entries()) {
        checkType(b64der, "string", `${field}.keys[${i}].x5c[${j}]`);
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64der)) {
          throw new Error(
            `${field}.keys[${i}].x5c[${j}] must be base64 encoded`,
          );
        }
        const pem =
          "-----BEGIN CERTIFICATE-----\n" +
          b64der +
          "\n-----END CERTIFICATE-----";
        checkX509CertBundle(pem, `${field}.keys[${i}].x5c[${j}]`);
        certBundle += pem;
      }
      const trustedRoot =
        "-----BEGIN CERTIFICATE-----\n" +
        jwk.x5c[jwk.x5c.length - 1] +
        "\n-----END CERTIFICATE-----";
      if (!ccf.crypto.isValidX509CertChain(certBundle, trustedRoot)) {
        throw new Error(`${field}.keys[${i}].x5c must chain to its root`);
      }
      if (jwk.n !== undefined || jwk.e !== undefined) {
        if (jwk.kty !== "RSA") {
          throw new Error(`${field}.keys[${i}].kty must be RSA for n/e keys`);
        }
        checkRsaPublicKey(jwk, keyField);
      }
      if (jwk.x !== undefined || jwk.y !== undefined || jwk.crv !== undefined) {
        if (jwk.kty !== "EC") {
          throw new Error(`${field}.keys[${i}].kty must be EC for x/y keys`);
        }
        checkEcPublicKey(jwk, keyField);
      }
    } else if (jwk.n && jwk.e) {
      if (jwk.kty !== "RSA") {
        throw new Error(`${field}.keys[${i}].kty must be RSA for n/e keys`);
      }
      checkRsaPublicKey(jwk, keyField);
    } else if (jwk.x && jwk.y) {
      if (jwk.kty !== "EC") {
        throw new Error(`${field}.keys[${i}].kty must be EC for x/y keys`);
      }
      checkEcPublicKey(jwk, keyField);
    } else {
      throw new Error(
        "JWK must contain either x5c, or n/e for RSA key type, or x/y/crv for EC key type",
      );
    }
  }
}

function checkX509CertBundle(value, field) {
  if (!ccf.crypto.isValidX509CertBundle(value)) {
    throw new Error(
      `${field} must be a valid X509 certificate (bundle) in PEM format`,
    );
  }
}

function invalidateOtherOpenProposals(proposalIdToRetain) {
  const proposalsMap = ccf.kv["public:ccf.gov.proposals_info"];
  proposalsMap.forEach((v, k) => {
    let proposalId = ccf.bufToStr(k);
    if (proposalId !== proposalIdToRetain) {
      let info = ccf.bufToJsonCompatible(v);
      if (info.state === "Open") {
        info.state = "Dropped";
        proposalsMap.set(k, ccf.jsonCompatibleToBuf(info));
      }
    }
  });
}

function setServiceCertificateValidityPeriod(validFrom, validityPeriodDays) {
  const rawConfig =
    ccf.kv["public:ccf.gov.service.config"].get(getSingletonKvKey());
  if (rawConfig === undefined) {
    throw new Error("Service configuration could not be found");
  }
  const serviceConfig = ccf.bufToJsonCompatible(rawConfig);

  const default_validity_period_days = 365;
  const max_allowed_cert_validity_period_days =
    serviceConfig.maximum_service_certificate_validity_days ??
    default_validity_period_days;

  if (
    validityPeriodDays !== undefined &&
    validityPeriodDays > max_allowed_cert_validity_period_days
  ) {
    throw new Error(
      `Validity period ${validityPeriodDays} (days) is not allowed: service max allowed is ${max_allowed_cert_validity_period_days} (days)`,
    );
  }

  const renewed_service_certificate = ccf.network.generateNetworkCertificate(
    validFrom,
    validityPeriodDays ?? max_allowed_cert_validity_period_days,
  );

  const serviceInfoTable = "public:ccf.gov.service.info";
  const rawServiceInfo = ccf.kv[serviceInfoTable].get(getSingletonKvKey());
  if (rawServiceInfo === undefined) {
    throw new Error("Service info could not be found");
  }
  const serviceInfo = ccf.bufToJsonCompatible(rawServiceInfo);

  serviceInfo.cert = renewed_service_certificate;
  ccf.kv[serviceInfoTable].set(
    getSingletonKvKey(),
    ccf.jsonCompatibleToBuf(serviceInfo),
  );
}

function setNodeCertificateValidityPeriod(
  nodeId,
  nodeInfo,
  validFrom,
  validityPeriodDays,
) {
  if (nodeInfo.certificate_signing_request === undefined) {
    throw new Error(`Node ${nodeId} has no certificate signing request`);
  }

  const rawConfig =
    ccf.kv["public:ccf.gov.service.config"].get(getSingletonKvKey());
  if (rawConfig === undefined) {
    throw new Error("Service configuration could not be found");
  }
  const serviceConfig = ccf.bufToJsonCompatible(rawConfig);

  const default_validity_period_days = 365;
  const max_allowed_cert_validity_period_days =
    serviceConfig.maximum_node_certificate_validity_days ??
    default_validity_period_days;

  if (
    validityPeriodDays !== undefined &&
    validityPeriodDays > max_allowed_cert_validity_period_days
  ) {
    throw new Error(
      `Validity period ${validityPeriodDays} (days) is not allowed: service max allowed is ${max_allowed_cert_validity_period_days} (days)`,
    );
  }

  const endorsed_node_cert = ccf.network.generateEndorsedCertificate(
    nodeInfo.certificate_signing_request,
    validFrom,
    validityPeriodDays ?? max_allowed_cert_validity_period_days,
  );
  ccf.kv["public:ccf.gov.nodes.endorsed_certificates"].set(
    ccf.strToBuf(nodeId),
    ccf.strToBuf(endorsed_node_cert),
  );
}

function checkRecoveryThreshold(config, new_config) {
  const from = config.recovery_threshold;
  const to = new_config.recovery_threshold;
  if (to === undefined || from === to) {
    return;
  }

  const serviceStatus = getServiceStatus();

  if (
    serviceStatus === "Recovering" ||
    serviceStatus === "WaitingForRecoveryShares"
  ) {
    throw new Error(
      `Cannot set recovery threshold if service is ${serviceStatus}`,
    );
  } else if (serviceStatus === "Open") {
    let activeRecoveryMembersCount = getActiveRecoveryMembersCount();
    if (new_config.recovery_threshold > activeRecoveryMembersCount) {
      throw new Error(
        `Cannot set recovery threshold to ${new_config.recovery_threshold}: recovery threshold would be greater than the number of recovery members ${activeRecoveryMembersCount}`,
      );
    }
  }
}

function checkReconfigurationType(config, new_config) {
  const from = config.reconfiguration_type;
  const to = new_config.reconfiguration_type;
  if (from !== to && to !== undefined) {
    if (!(
      (from === undefined || from === "OneTransaction") &&
      to === "TwoTransaction"
    )) {
      throw new Error(
        `Cannot change reconfiguration type from ${from} to ${to}.`,
      );
    }
  }
}

function updateServiceConfig(new_config) {
  const service_config_table = "public:ccf.gov.service.config";
  const rawConfig = ccf.kv[service_config_table].get(getSingletonKvKey());
  if (rawConfig === undefined) {
    throw new Error("Service configuration could not be found");
  }
  let config = ccf.bufToJsonCompatible(rawConfig);

  // First run all checks
  checkReconfigurationType(config, new_config);
  checkRecoveryThreshold(config, new_config);

  // Then all updates
  if (new_config.reconfiguration_type !== undefined) {
    config.reconfiguration_type = new_config.reconfiguration_type;
  }

  let need_recovery_threshold_refresh = false;
  if (
    new_config.recovery_threshold !== undefined &&
    new_config.recovery_threshold !== config.recovery_threshold
  ) {
    config.recovery_threshold = new_config.recovery_threshold;
    need_recovery_threshold_refresh = true;
  }

  if (new_config.recent_cose_proposals_window_size !== undefined) {
    config.recent_cose_proposals_window_size =
      new_config.recent_cose_proposals_window_size;
  }

  ccf.kv[service_config_table].set(
    getSingletonKvKey(),
    ccf.jsonCompatibleToBuf(config),
  );

  if (need_recovery_threshold_refresh) {
    ccf.node.triggerRecoverySharesRefresh();
  }
}

const actions = new Map([
  [
    "set_constitution",
    new Action(
      function (args) {
        checkType(args.constitution, "string", "constitution");
        ccf.gov.validateConstitution(args.constitution);
      },
      function (args, proposalId) {
        ccf.kv["public:ccf.gov.constitution"].set(
          getSingletonKvKey(),
          ccf.jsonCompatibleToBuf(args.constitution),
        );

        // Changing the constitution changes the semantics of any other open proposals, so invalidate them to avoid confusion or malicious vote modification
        invalidateOtherOpenProposals(proposalId);
      },
    ),
  ],
  [
    "set_member",
    new Action(
      function (args) {
        checkX509CertBundle(args.cert, "cert");
        checkType(args.member_data, "object?", "member_data");
        const recovery_role = args.recovery_role;
        if (recovery_role !== undefined) {
          checkEnum(
            recovery_role,
            ["NonParticipant", "Participant", "Owner"],
            "recovery_role",
          );
        }

        if (
          args.encryption_pub_key == null &&
          args.recovery_role !== null &&
          args.recovery_role !== undefined
        ) {
          throw new Error(
            "Cannot specify a recovery_role value when encryption_pub_key is not specified",
          );
        }
        if (
          args.encryption_pub_key !== null &&
          args.encryption_pub_key !== undefined
        ) {
          checkRsaPublicKey(
            ccf.crypto.pubRsaPemToJwk(args.encryption_pub_key),
            "encryption_pub_key",
          );
        }

        checkRecoveryMemberChange(
          ccf.strToBuf(ccf.pemToId(args.cert)),
          args.encryption_pub_key !== null &&
            args.encryption_pub_key !== undefined,
        );
      },

      function (args) {
        const memberId = ccf.pemToId(args.cert);
        const rawMemberId = ccf.strToBuf(memberId);
        checkRecoveryMemberChange(
          rawMemberId,
          args.encryption_pub_key !== null &&
            args.encryption_pub_key !== undefined,
        );

        ccf.kv["public:ccf.gov.members.certs"].set(
          rawMemberId,
          ccf.strToBuf(args.cert),
        );

        if (args.encryption_pub_key == null) {
          ccf.kv["public:ccf.gov.members.encryption_public_keys"].delete(
            rawMemberId,
          );
        } else {
          ccf.kv["public:ccf.gov.members.encryption_public_keys"].set(
            rawMemberId,
            ccf.strToBuf(args.encryption_pub_key),
          );
        }

        let member_info = {};
        member_info.member_data = args.member_data;
        member_info.recovery_role = args.recovery_role;
        member_info.status = "Accepted";
        ccf.kv["public:ccf.gov.members.info"].set(
          rawMemberId,
          ccf.jsonCompatibleToBuf(member_info),
        );

        const rawSignature =
          ccf.kv["public:ccf.internal.signatures"].get(getSingletonKvKey());
        if (rawSignature === undefined) {
          ccf.kv["public:ccf.gov.members.acks"].set(rawMemberId);
        } else {
          const signature = ccf.bufToJsonCompatible(rawSignature);
          const ack = {};
          ack.state_digest = signature.root;
          ccf.kv["public:ccf.gov.members.acks"].set(
            rawMemberId,
            ccf.jsonCompatibleToBuf(ack),
          );
        }
      },
    ),
  ],
  [
    "remove_member",
    new Action(
      function (args) {
        checkEntityId(args.member_id, "member_id");
        checkRecoveryMemberChange(ccf.strToBuf(args.member_id), false);
      },
      function (args) {
        const rawMemberId = ccf.strToBuf(args.member_id);
        checkRecoveryMemberChange(rawMemberId, false);
        const rawMemberInfo =
          ccf.kv["public:ccf.gov.members.info"].get(rawMemberId);
        if (rawMemberInfo === undefined) {
          return; // Idempotent
        }

        const memberInfo = ccf.bufToJsonCompatible(rawMemberInfo);
        const isActiveMember = memberInfo.status == "Active";

        const isRecoveryMember = ccf.kv[
          "public:ccf.gov.members.encryption_public_keys"
        ].has(rawMemberId)
          ? true
          : false;

        // If the member is an active recovery member, check that there
        // would still be a sufficient number of recovery members left
        // to recover the service
        if (isActiveMember && isRecoveryMember) {
          const rawConfig =
            ccf.kv["public:ccf.gov.service.config"].get(getSingletonKvKey());
          if (rawConfig === undefined) {
            throw new Error("Service configuration could not be found");
          }

          const config = ccf.bufToJsonCompatible(rawConfig);
          const activeRecoveryMembersCountAfter =
            getActiveRecoveryMembersCount() - 1;
          if (activeRecoveryMembersCountAfter < config.recovery_threshold) {
            throw new Error(
              `Number of active recovery members (${activeRecoveryMembersCountAfter}) would be less than recovery threshold (${config.recovery_threshold})`,
            );
          }
        }

        ccf.kv["public:ccf.gov.members.info"].delete(rawMemberId);
        ccf.kv["public:ccf.gov.members.encryption_public_keys"].delete(
          rawMemberId,
        );
        ccf.kv["public:ccf.gov.members.certs"].delete(rawMemberId);
        ccf.kv["public:ccf.gov.members.acks"].delete(rawMemberId);
        ccf.kv["public:ccf.gov.history"].delete(rawMemberId);

        if (isActiveMember && isRecoveryMember) {
          // A retired recovery member should not have access to the private
          // ledger going forward so rekey the ledger, issuing new shares to
          // remaining active recovery members
          ccf.node.triggerLedgerRekey();
        }
      },
    ),
  ],
  [
    "set_member_data",
    new Action(
      function (args) {
        checkEntityId(args.member_id, "member_id");
        checkType(args.member_data, "object", "member_data");
      },

      function (args) {
        let member_id = ccf.strToBuf(args.member_id);
        let members_info = ccf.kv["public:ccf.gov.members.info"];
        let member_info = members_info.get(member_id);
        if (member_info === undefined) {
          throw new Error(`Member ${args.member_id} does not exist`);
        }
        let mi = ccf.bufToJsonCompatible(member_info);
        mi.member_data = args.member_data;
        members_info.set(member_id, ccf.jsonCompatibleToBuf(mi));
      },
    ),
  ],
  [
    "set_user",
    new Action(
      function (args) {
        checkX509CertBundle(args.cert, "cert");
        checkType(args.user_data, "object?", "user_data");
      },
      function (args) {
        let userId = ccf.pemToId(args.cert);
        let rawUserId = ccf.strToBuf(userId);

        ccf.kv["public:ccf.gov.users.certs"].set(
          rawUserId,
          ccf.strToBuf(args.cert),
        );

        if (args.user_data !== null && args.user_data !== undefined) {
          let userInfo = {};
          userInfo.user_data = args.user_data;
          ccf.kv["public:ccf.gov.users.info"].set(
            rawUserId,
            ccf.jsonCompatibleToBuf(userInfo),
          );
        } else {
          ccf.kv["public:ccf.gov.users.info"].delete(rawUserId);
        }
      },
    ),
  ],
  [
    "remove_user",
    new Action(
      function (args) {
        checkEntityId(args.user_id, "user_id");
      },
      function (args) {
        const user_id = ccf.strToBuf(args.user_id);
        ccf.kv["public:ccf.gov.users.certs"].delete(user_id);
        ccf.kv["public:ccf.gov.users.info"].delete(user_id);
      },
    ),
  ],
  [
    "set_user_data",
    new Action(
      function (args) {
        checkEntityId(args.user_id, "user_id");
        checkType(args.user_data, "object?", "user_data");
      },
      function (args) {
        const userId = ccf.strToBuf(args.user_id);

        if (args.user_data !== null && args.user_data !== undefined) {
          let userInfo = {};
          userInfo.user_data = args.user_data;
          ccf.kv["public:ccf.gov.users.info"].set(
            userId,
            ccf.jsonCompatibleToBuf(userInfo),
          );
        } else {
          ccf.kv["public:ccf.gov.users.info"].delete(userId);
        }
      },
    ),
  ],
  [
    "set_recovery_threshold",
    new Action(
      function (args) {
        checkType(args.recovery_threshold, "integer", "threshold");
        checkBounds(args.recovery_threshold, 1, 254, "threshold");
        checkRecoverySharesChange();
      },
      function (args) {
        checkRecoverySharesChange();
        updateServiceConfig(args);
      },
    ),
  ],
  [
    "trigger_recovery_shares_refresh",
    new Action(
      function (args) {
        checkNone(args);
        checkRecoverySharesChange();
      },
      function (args) {
        checkRecoverySharesChange();
        ccf.node.triggerRecoverySharesRefresh();
      },
    ),
  ],
  [
    "trigger_ledger_rekey",
    new Action(
      function (args) {
        checkNone(args);
        checkRecoverySharesChange();
      },

      function (args) {
        checkRecoverySharesChange();
        ccf.node.triggerLedgerRekey();
      },
    ),
  ],
  [
    "transition_service_to_open",
    new Action(
      function (args) {
        checkType(
          args.next_service_identity,
          "string",
          "next service identity (PEM certificate)",
        );
        checkX509CertBundle(
          args.next_service_identity,
          "next_service_identity",
        );

        checkType(
          args.previous_service_identity,
          "string?",
          "previous service identity (PEM certificate)",
        );
        if (args.previous_service_identity !== undefined) {
          checkX509CertBundle(
            args.previous_service_identity,
            "previous_service_identity",
          );
        }
      },

      function (args) {
        const service_info = "public:ccf.gov.service.info";
        const rawService = ccf.kv[service_info].get(getSingletonKvKey());
        if (rawService === undefined) {
          throw new Error("Service information could not be found");
        }

        const service = ccf.bufToJsonCompatible(rawService);

        if (
          service.status === "Recovering" &&
          (args.previous_service_identity === undefined ||
            args.next_service_identity === undefined)
        ) {
          throw new Error(
            `Opening a recovering network requires both, the previous and the next service identity`,
          );
        }

        const previous_identity =
          args.previous_service_identity !== undefined
            ? ccf.strToBuf(args.previous_service_identity)
            : undefined;
        const next_identity = ccf.strToBuf(args.next_service_identity);
        ccf.node.transitionServiceToOpen(previous_identity, next_identity);
      },
    ),
  ],
  [
    "set_js_app",
    new Action(
      function (args) {
        const bundle = args.bundle;
        checkType(bundle, "object", "bundle");

        let prefix = "bundle.modules";
        checkType(bundle.modules, "array", prefix);
        for (const [i, module] of bundle.modules.entries()) {
          checkType(module, "object", `${prefix}[${i}]`);
          checkType(module.name, "string", `${prefix}[${i}].name`);
          checkType(module.module, "string", `${prefix}[${i}].module`);
        }

        prefix = "bundle.metadata";
        checkType(bundle.metadata, "object", prefix);
        checkType(bundle.metadata.endpoints, "object", `${prefix}.endpoints`);
        for (const [url, endpoint] of Object.entries(
          bundle.metadata.endpoints,
        )) {
          checkType(endpoint, "object", `${prefix}.endpoints["${url}"]`);
          for (const [method, info] of Object.entries(endpoint)) {
            const prefix2 = `${prefix}.endpoints["${url}"]["${method}"]`;
            checkType(info, "object", prefix2);
            checkType(info.js_module, "string", `${prefix2}.js_module`);
            checkType(info.js_function, "string", `${prefix2}.js_function`);
            checkEnum(
              info.mode,
              ["readwrite", "readonly", "historical"],
              `${prefix2}.mode`,
            );
            checkEnum(
              info.forwarding_required,
              ["sometimes", "always", "never"],
              `${prefix2}.forwarding_required`,
            );

            const redirection_strategy = info.redirection_strategy;
            if (redirection_strategy !== undefined) {
              checkEnum(
                info.redirection_strategy,
                ["none", "to_primary", "to_backup"],
                `${prefix2}.redirection_strategy`,
              );
            }

            checkType(info.openapi, "object?", `${prefix2}.openapi`);
            checkType(
              info.openapi_hidden,
              "boolean?",
              `${prefix2}.openapi_hidden`,
            );
            checkType(
              info.authn_policies,
              "array",
              `${prefix2}.authn_policies`,
            );
            for (const [i, policy] of info.authn_policies.entries()) {
              if (typeof policy === "string") {
                // May still be an unrecognised value. That will only throw later
                continue;
              } else if (typeof policy === "object") {
                const constituents = policy["all_of"];
                checkType(
                  constituents,
                  "array",
                  `${prefix2}.authn_policies[${i}].all_of`,
                );
                for (const [j, sub_policy] of constituents.entries()) {
                  checkType(
                    sub_policy,
                    "string",
                    `${prefix2}.authn_policies[${i}].all_of[${j}]`,
                  );
                }
              } else {
                throw new Error(
                  `${prefix2}.authn_policies[${i}] must be of type string or object but is ${typeof policy}`,
                );
              }
            }
            if (!bundle.modules.some((m) => m.name === info.js_module)) {
              throw new Error(`module '${info.js_module}' not found in bundle`);
            }
          }
        }

        checkType(
          args.disable_bytecode_cache,
          "boolean?",
          "disable_bytecode_cache",
        );
      },
      function (args) {
        const modulesMap = ccf.kv["public:ccf.gov.modules"];
        const modulesQuickJsBytecodeMap =
          ccf.kv["public:ccf.gov.modules_quickjs_bytecode"];
        const modulesQuickJsVersionVal =
          ccf.kv["public:ccf.gov.modules_quickjs_version"];
        const interpreterFlushVal = ccf.kv["public:ccf.gov.interpreter.flush"];
        const endpointsMap = ccf.kv["public:ccf.gov.endpoints"];
        modulesMap.clear();
        endpointsMap.clear();

        const bundle = args.bundle;
        for (const module of bundle.modules) {
          const path = "/" + module.name;
          const pathBuf = ccf.strToBuf(path);
          const moduleBuf = ccf.strToBuf(module.module);
          modulesMap.set(pathBuf, moduleBuf);
        }

        if (args.disable_bytecode_cache) {
          modulesQuickJsBytecodeMap.clear();
          modulesQuickJsVersionVal.clear();
        } else {
          ccf.refreshAppBytecodeCache();
        }

        interpreterFlushVal.set(
          getSingletonKvKey(),
          ccf.jsonCompatibleToBuf(true),
        );

        for (const [url, endpoint] of Object.entries(
          bundle.metadata.endpoints,
        )) {
          for (const [method, info] of Object.entries(endpoint)) {
            const key = `${method.toUpperCase()} ${url}`;
            const keyBuf = ccf.strToBuf(key);

            info.js_module = "/" + info.js_module;
            const infoBuf = ccf.jsonCompatibleToBuf(info);
            endpointsMap.set(keyBuf, infoBuf);
          }
        }
      },
    ),
  ],
  [
    "remove_js_app",
    new Action(
      function (args) {},
      function (args) {
        const modulesMap = ccf.kv["public:ccf.gov.modules"];
        const modulesQuickJsBytecodeMap =
          ccf.kv["public:ccf.gov.modules_quickjs_bytecode"];
        const interpreterFlushVal = ccf.kv["public:ccf.gov.interpreter.flush"];
        const modulesQuickJsVersionVal =
          ccf.kv["public:ccf.gov.modules_quickjs_version"];
        const endpointsMap = ccf.kv["public:ccf.gov.endpoints"];
        modulesMap.clear();
        modulesQuickJsBytecodeMap.clear();
        modulesQuickJsVersionVal.clear();
        interpreterFlushVal.clear();
        endpointsMap.clear();
      },
    ),
  ],
  [
    "set_js_runtime_options",
    new Action(
      function (args) {
        checkType(args.max_heap_bytes, "integer", "max_heap_bytes");
        checkType(args.max_stack_bytes, "integer", "max_stack_bytes");
        checkType(
          args.max_execution_time_ms,
          "integer",
          "max_execution_time_ms",
        );
        checkType(
          args.log_exception_details,
          "boolean?",
          "log_exception_details",
        );
        checkType(
          args.return_exception_details,
          "boolean?",
          "return_exception_details",
        );
        checkType(
          args.max_cached_interpreters,
          "integer?",
          "max_cached_interpreters",
        );
      },
      function (args) {
        const js_engine_map = ccf.kv["public:ccf.gov.js_runtime_options"];
        js_engine_map.set(getSingletonKvKey(), ccf.jsonCompatibleToBuf(args));
      },
    ),
  ],
  [
    "refresh_js_app_bytecode_cache",
    new Action(
      function (args) {},
      function (args) {
        ccf.refreshAppBytecodeCache();
      },
    ),
  ],
  [
    "set_ca_cert_bundle",
    new Action(
      function (args) {
        checkType(args.name, "string", "name");
        checkX509CACertBundle(args.cert_bundle, "cert_bundle");
      },
      function (args) {
        const name = args.name;
        const bundle = args.cert_bundle;
        const nameBuf = ccf.strToBuf(name);
        const bundleBuf = ccf.jsonCompatibleToBuf(bundle);
        ccf.kv["public:ccf.gov.tls.ca_cert_bundles"].set(nameBuf, bundleBuf);
      },
    ),
  ],
  [
    "remove_ca_cert_bundle",
    new Action(
      function (args) {
        checkType(args.name, "string", "name");
      },
      function (args) {
        const name = args.name;
        const nameBuf = ccf.strToBuf(name);
        ccf.kv["public:ccf.gov.tls.ca_cert_bundles"].delete(nameBuf);
      },
    ),
  ],
  [
    "set_jwt_issuer",
    new Action(
      function (args) {
        checkType(args.issuer, "string", "issuer");
        checkType(args.auto_refresh, "boolean?", "auto_refresh");
        checkType(args.ca_cert_bundle_name, "string?", "ca_cert_bundle_name");
        checkType(args.jwks, "object?", "jwks");
        if (args.jwks) {
          checkJwks(args.jwks, "jwks");
        }
        let url;
        try {
          url = parseUrl(args.issuer);
        } catch (e) {
          throw new Error("issuer must be a URL");
        }
        if (url.scheme != "https" || !url.authority) {
          throw new Error("issuer must be a URL starting with https://");
        }
        if (url.query || url.fragment) {
          throw new Error("issuer must be a URL without query/fragment");
        }
        if (args.auto_refresh) {
          if (!args.ca_cert_bundle_name) {
            throw new Error(
              "ca_cert_bundle_name is missing but required if auto_refresh is true",
            );
          }
        }
      },
      function (args) {
        if (args.auto_refresh) {
          const caCertBundleName = args.ca_cert_bundle_name;
          const caCertBundleNameBuf = ccf.strToBuf(args.ca_cert_bundle_name);
          if (
            !ccf.kv["public:ccf.gov.tls.ca_cert_bundles"].has(
              caCertBundleNameBuf,
            )
          ) {
            throw new Error(
              `No CA cert bundle found with name '${caCertBundleName}'`,
            );
          }
        }
        const issuer = args.issuer;
        const jwks = args.jwks;
        delete args.jwks;
        const metadata = args;
        if (jwks) {
          ccf.setJwtPublicSigningKeys(issuer, metadata, jwks);
        }
        const issuerBuf = ccf.strToBuf(issuer);
        const metadataBuf = ccf.jsonCompatibleToBuf(metadata);
        ccf.kv["public:ccf.gov.jwt.issuers"].set(issuerBuf, metadataBuf);
      },
    ),
  ],
  [
    "set_jwt_public_signing_keys",
    new Action(
      function (args) {
        checkType(args.issuer, "string", "issuer");
        checkJwks(args.jwks, "jwks");
      },
      function (args) {
        const issuer = args.issuer;
        const issuerBuf = ccf.strToBuf(issuer);
        const metadataBuf = ccf.kv["public:ccf.gov.jwt.issuers"].get(issuerBuf);
        if (metadataBuf === undefined) {
          throw new Error(`issuer ${issuer} not found`);
        }
        const metadata = ccf.bufToJsonCompatible(metadataBuf);
        const jwks = args.jwks;
        ccf.setJwtPublicSigningKeys(issuer, metadata, jwks);
      },
    ),
  ],
  [
    "remove_jwt_issuer",
    new Action(
      function (args) {
        checkType(args.issuer, "string", "issuer");
      },
      function (args) {
        const issuerBuf = ccf.strToBuf(args.issuer);
        if (!ccf.kv["public:ccf.gov.jwt.issuers"].has(issuerBuf)) {
          return;
        }
        ccf.kv["public:ccf.gov.jwt.issuers"].delete(issuerBuf);
        ccf.removeJwtPublicSigningKeys(args.issuer);
      },
    ),
  ],
  [
    "add_snp_measurement",
    new Action(
      function (args) {
        checkType(args.measurement, "string", "measurement");
      },
      function (args, proposalId) {
        const measurement = ccf.strToBuf(args.measurement);
        const ALLOWED = ccf.jsonCompatibleToBuf("AllowedToJoin");
        ccf.kv["public:ccf.gov.nodes.snp.measurements"].set(
          measurement,
          ALLOWED,
        );

        // Adding a new allowed measurement changes the semantics of any other open proposals, so invalidate them to avoid confusion or malicious vote modification
        invalidateOtherOpenProposals(proposalId);
      },
    ),
  ],
  [
    "add_snp_uvm_endorsement",
    new Action(
      function (args) {
        checkType(args.did, "string", "did");
        checkType(args.feed, "string", "feed");
        checkType(args.svn, "string", "svn");
      },
      function (args, proposalId) {
        let uvmEndorsementsForDID = ccf.kv[
          "public:ccf.gov.nodes.snp.uvm_endorsements"
        ].get(ccf.strToBuf(args.did));
        let uvme = {};
        if (uvmEndorsementsForDID !== undefined) {
          uvme = ccf.bufToJsonCompatible(uvmEndorsementsForDID);
        }
        uvme[args.feed] = { svn: args.svn };
        ccf.kv["public:ccf.gov.nodes.snp.uvm_endorsements"].set(
          ccf.strToBuf(args.did),
          ccf.jsonCompatibleToBuf(uvme),
        );
        // Adding a new allowed UVM endorsement changes the semantics of any other open proposals, so invalidate them to avoid confusion or malicious vote modification
        invalidateOtherOpenProposals(proposalId);
      },
    ),
  ],
  [
    "add_snp_host_data",
    new Action(
      function (args) {
        checkType(args.security_policy, "string", "security_policy");
        checkType(args.host_data, "string", "host_data");

        // If optional security policy is specified, make sure its
        // SHA-256 digest is the specified host data
        if (args.security_policy != "") {
          const securityPolicyDigest = ccf.bufToStr(
            ccf.crypto.digest("SHA-256", ccf.strToBuf(args.security_policy)),
          );
          const hostData = ccf.bufToStr(hexStrToBuf(args.host_data));
          if (securityPolicyDigest != hostData) {
            throw new Error(
              `The hash of raw policy ${securityPolicyDigest} does not match digest ${hostData}`,
            );
          }
        }
      },
      function (args, proposalId) {
        ccf.kv["public:ccf.gov.nodes.snp.host_data"].set(
          ccf.strToBuf(args.host_data),
          ccf.jsonCompatibleToBuf(args.security_policy),
        );

        // Adding a new allowed host data changes the semantics of any other open proposals, so invalidate them to avoid confusion or malicious vote modification
        invalidateOtherOpenProposals(proposalId);
      },
    ),
  ],
  [
    "set_snp_minimum_tcb_version",
    new Action(
      function (args) {
        checkValidCpuid(args.cpuid, "cpuid");

        checkType(args.tcb_version, "object", "tcb_version");
        checkType(
          args.tcb_version?.boot_loader,
          "number",
          "tcb_version.boot_loader",
        );
        checkType(args.tcb_version?.tee, "number", "tcb_version.tee");
        checkType(args.tcb_version?.snp, "number", "tcb_version.snp");
        checkType(
          args.tcb_version?.microcode,
          "number",
          "tcb_version.microcode",
        );
      },
      function (args, proposalId) {
        ccf.kv["public:ccf.gov.nodes.snp.tcb_versions"].set(
          ccf.strToBuf(args.cpuid),
          ccf.jsonCompatibleToBuf(args.tcb_version),
        );

        invalidateOtherOpenProposals(proposalId);
      },
    ),
  ],
  [
    "set_snp_minimum_tcb_version_hex",
    new Action(
      function (args) {
        checkValidCpuid(args.cpuid, "cpuid");
        checkValidTcbVersionHex(args.tcb_version, "tcb_version");
      },
      function (args, proposalId) {
        let tcb_policy = ccf.tcbHexToPolicy(args.cpuid, args.tcb_version);
        ccf.kv["public:ccf.gov.nodes.snp.tcb_versions"].set(
          ccf.strToBuf(args.cpuid),
          ccf.jsonCompatibleToBuf(tcb_policy),
        );

        invalidateOtherOpenProposals(proposalId);
      },
    ),
  ],
  [
    "remove_snp_host_data",
    new Action(
      function (args) {
        checkType(args.host_data, "string", "host_data");
      },
      function (args) {
        const hostData = ccf.strToBuf(args.host_data);
        ccf.kv["public:ccf.gov.nodes.snp.host_data"].delete(hostData);
      },
    ),
  ],
  [
    "remove_snp_measurement",
    new Action(
      function (args) {
        checkType(args.measurement, "string", "measurement");
      },
      function (args) {
        const measurement = ccf.strToBuf(args.measurement);
        ccf.kv["public:ccf.gov.nodes.snp.measurements"].delete(measurement);
      },
    ),
  ],
  [
    "remove_snp_uvm_endorsement",
    new Action(
      function (args) {
        checkType(args.did, "string", "did");
        checkType(args.feed, "string", "feed");
      },
      function (args) {
        let uvmEndorsementsForDID = ccf.kv[
          "public:ccf.gov.nodes.snp.uvm_endorsements"
        ].get(ccf.strToBuf(args.did));
        let uvme = {};
        if (uvmEndorsementsForDID !== undefined) {
          uvme = ccf.bufToJsonCompatible(uvmEndorsementsForDID);
        }
        delete uvme[args.feed];

        if (Object.keys(uvme).length === 0) {
          // Delete DID if no feed are left
          ccf.kv["public:ccf.gov.nodes.snp.uvm_endorsements"].delete(
            ccf.strToBuf(args.did),
          );
        } else {
          ccf.kv["public:ccf.gov.nodes.snp.uvm_endorsements"].set(
            ccf.strToBuf(args.did),
            ccf.jsonCompatibleToBuf(uvme),
          );
        }
      },
    ),
  ],
  [
    "remove_snp_minimum_tcb_version",
    new Action(
      function (args) {
        checkValidCpuid(args.cpuid, "cpuid");
      },
      function (args) {
        const cpuid = ccf.strToBuf(args.cpuid);
        if (ccf.kv["public:ccf.gov.nodes.snp.tcb_versions"].has(cpuid)) {
          ccf.kv["public:ccf.gov.nodes.snp.tcb_versions"].delete(cpuid);
        } else {
          throw new Error(`CPUID ${args.cpuid} not found`);
        }
      },
    ),
  ],
  [
    "set_node_data",
    new Action(
      function (args) {
        checkEntityId(args.node_id, "node_id");
      },
      function (args) {
        let node_id = ccf.strToBuf(args.node_id);
        let nodes_info = ccf.kv["public:ccf.gov.nodes.info"];
        let node_info = nodes_info.get(node_id);
        if (node_info === undefined) {
          throw new Error(`Node ${node_id} does not exist`);
        }
        let ni = ccf.bufToJsonCompatible(node_info);
        ni.node_data = args.node_data;
        nodes_info.set(node_id, ccf.jsonCompatibleToBuf(ni));
      },
    ),
  ],
  [
    "transition_node_to_trusted",
    new Action(
      function (args) {
        checkEntityId(args.node_id, "node_id");
        checkType(args.valid_from, "string", "valid_from");
        if (args.validity_period_days !== undefined) {
          checkType(
            args.validity_period_days,
            "integer",
            "validity_period_days",
          );
          checkBounds(
            args.validity_period_days,
            1,
            null,
            "validity_period_days",
          );
        }
      },
      function (args) {
        const rawConfig =
          ccf.kv["public:ccf.gov.service.config"].get(getSingletonKvKey());
        if (rawConfig === undefined) {
          throw new Error("Service configuration could not be found");
        }
        const serviceConfig = ccf.bufToJsonCompatible(rawConfig);
        const node = ccf.kv["public:ccf.gov.nodes.info"].get(
          ccf.strToBuf(args.node_id),
        );
        if (node === undefined) {
          throw new Error(`No such node: ${args.node_id}`);
        }
        const nodeInfo = ccf.bufToJsonCompatible(node);
        if (nodeInfo.status === "Pending") {
          nodeInfo.status = "Trusted";
          nodeInfo.ledger_secret_seqno =
            ccf.network.getLatestLedgerSecretSeqno();
          ccf.kv["public:ccf.gov.nodes.info"].set(
            ccf.strToBuf(args.node_id),
            ccf.jsonCompatibleToBuf(nodeInfo),
          );
          if (ccf.node.shuffleSealedShares !== undefined) {
            ccf.node.shuffleSealedShares();
          }

          // Also generate and record service-endorsed node certificate from node CSR
          if (nodeInfo.certificate_signing_request !== undefined) {
            // Note: CSR and node certificate validity config are only present from 2.x
            const default_validity_period_days = 365;
            const max_allowed_cert_validity_period_days =
              serviceConfig.maximum_node_certificate_validity_days ??
              default_validity_period_days;
            if (
              args.validity_period_days !== undefined &&
              args.validity_period_days > max_allowed_cert_validity_period_days
            ) {
              throw new Error(
                `Validity period ${args.validity_period_days} is not allowed: max allowed is ${max_allowed_cert_validity_period_days}`,
              );
            }

            const endorsed_node_cert = ccf.network.generateEndorsedCertificate(
              nodeInfo.certificate_signing_request,
              args.valid_from,
              args.validity_period_days ??
                max_allowed_cert_validity_period_days,
            );
            ccf.kv["public:ccf.gov.nodes.endorsed_certificates"].set(
              ccf.strToBuf(args.node_id),
              ccf.strToBuf(endorsed_node_cert),
            );
          }
        }
      },
    ),
  ],
  [
    "remove_node",
    new Action(
      function (args) {
        checkEntityId(args.node_id, "node_id");
      },
      function (args) {
        const rawConfig =
          ccf.kv["public:ccf.gov.service.config"].get(getSingletonKvKey());
        if (rawConfig === undefined) {
          throw new Error("Service configuration could not be found");
        }
        const serviceConfig = ccf.bufToJsonCompatible(rawConfig);
        const node = ccf.kv["public:ccf.gov.nodes.info"].get(
          ccf.strToBuf(args.node_id),
        );
        if (node === undefined) {
          return;
        }
        const node_obj = ccf.bufToJsonCompatible(node);
        if (node_obj.status === "Pending") {
          ccf.kv["public:ccf.gov.nodes.info"].delete(
            ccf.strToBuf(args.node_id),
          );
        } else {
          node_obj.status = "Retired";
          ccf.kv["public:ccf.gov.nodes.info"].set(
            ccf.strToBuf(args.node_id),
            ccf.jsonCompatibleToBuf(node_obj),
          );
        }
      },
    ),
  ],
  [
    "set_node_certificate_validity",
    new Action(
      function (args) {
        checkEntityId(args.node_id, "node_id");
        checkType(args.valid_from, "string", "valid_from");
        if (args.validity_period_days !== undefined) {
          checkType(
            args.validity_period_days,
            "integer",
            "validity_period_days",
          );
          checkBounds(
            args.validity_period_days,
            1,
            null,
            "validity_period_days",
          );
        }
      },
      function (args) {
        const node = ccf.kv["public:ccf.gov.nodes.info"].get(
          ccf.strToBuf(args.node_id),
        );
        if (node === undefined) {
          throw new Error(`No such node: ${args.node_id}`);
        }
        const nodeInfo = ccf.bufToJsonCompatible(node);
        if (nodeInfo.status !== "Trusted") {
          throw new Error(`Node ${args.node_id} is not trusted`);
        }

        setNodeCertificateValidityPeriod(
          args.node_id,
          nodeInfo,
          args.valid_from,
          args.validity_period_days,
        );
      },
    ),
  ],
  [
    "set_all_nodes_certificate_validity",
    new Action(
      function (args) {
        checkType(args.valid_from, "string", "valid_from");
        if (args.validity_period_days !== undefined) {
          checkType(
            args.validity_period_days,
            "integer",
            "validity_period_days",
          );
          checkBounds(
            args.validity_period_days,
            1,
            null,
            "validity_period_days",
          );
        }
      },
      function (args) {
        ccf.kv["public:ccf.gov.nodes.info"].forEach((v, k) => {
          const nodeId = ccf.bufToStr(k);
          const nodeInfo = ccf.bufToJsonCompatible(v);
          if (nodeInfo.status === "Trusted") {
            setNodeCertificateValidityPeriod(
              nodeId,
              nodeInfo,
              args.valid_from,
              args.validity_period_days,
            );
          }
        });
      },
    ),
  ],
  [
    "set_service_certificate_validity",
    new Action(
      function (args) {
        checkType(args.valid_from, "string", "valid_from");
        if (args.validity_period_days !== undefined) {
          checkType(
            args.validity_period_days,
            "integer",
            "validity_period_days",
          );
          checkBounds(
            args.validity_period_days,
            1,
            null,
            "validity_period_days",
          );
        }
      },
      function (args) {
        setServiceCertificateValidityPeriod(
          args.valid_from,
          args.validity_period_days,
        );
      },
    ),
  ],
  [
    "set_service_configuration",
    new Action(
      function (args) {
        for (var key in args) {
          if (
            ![
              "reconfiguration_type",
              "recovery_threshold",
              "recent_cose_proposals_window_size",
            ].includes(key)
          ) {
            throw new Error(
              `Cannot change ${key} via set_service_configuration.`,
            );
          }
        }
        checkType(args.reconfiguration_type, "string?", "reconfiguration type");
        checkType(args.recovery_threshold, "integer?", "recovery threshold");
        checkBounds(args.recovery_threshold, 1, 254, "recovery threshold");
        checkType(
          args.recent_cose_proposals_window_size,
          "integer?",
          "recent cose proposals window size",
        );
        checkBounds(
          args.recent_cose_proposals_window_size,
          1,
          10000,
          "recent cose proposals window size",
        );
      },
      function (args) {
        updateServiceConfig(args);
      },
    ),
  ],
  [
    "trigger_ledger_chunk",
    new Action(
      function (args) {},
      function (args, proposalId) {
        ccf.node.triggerLedgerChunk();
      },
    ),
  ],
  [
    "trigger_snapshot",
    new Action(
      function (args) {},
      function (args, proposalId) {
        ccf.node.triggerSnapshot();
      },
    ),
  ],
  [
    "assert_service_identity",
    new Action(
      function (args) {
        checkX509CertBundle(args.service_identity, "service_identity");
        const service_info = "public:ccf.gov.service.info";
        const rawService = ccf.kv[service_info].get(getSingletonKvKey());
        if (rawService === undefined) {
          throw new Error("Service information could not be found");
        }
        const service = ccf.bufToJsonCompatible(rawService);
        if (service.cert !== args.service_identity) {
          throw new Error("Service identity certificate mismatch");
        }
      },
      function (args) {},
    ),
  ],
  [
    "cleanup_legacy_jwt_records",
    new Action(
      function (args) {
        checkType(
          args.ensure_new_records_exist,
          "boolean?",
          "ensure_new_records_exist",
        );
      },
      function (args) {
        if (
          args.ensure_new_records_exist &&
          ccf.kv["public:ccf.gov.jwt.public_signing_keys_metadata_v2"].size ===
            0
        ) {
          throw new Error("No new JWT public signing keys records found");
        }

        ccf.kv["public:ccf.gov.jwt.public_signing_keys"].clear();
        ccf.kv["public:ccf.gov.jwt.public_signing_keys_metadata"].clear();
        ccf.kv["public:ccf.gov.jwt.public_signing_key_issuer"].clear();
      },
    ),
  ],
  [
    "set_node_join_policy",
    new Action(
      function (args) {
        checkType(args.policy, "string", "policy");
      },
      function (args, proposalId) {
        const codeUpdatePolicyTable =
          ccf.kv["public:ccf.gov.nodes.node_join_policy"];
        codeUpdatePolicyTable.set(
          getSingletonKvKey(),
          ccf.strToBuf(args.policy),
        );
      },
    ),
  ],
  [
    "remove_node_join_policy",
    new Action(
      function (args) {},
      function (args, proposalId) {
        const codeUpdatePolicyTable =
          ccf.kv["public:ccf.gov.nodes.node_join_policy"];
        codeUpdatePolicyTable.delete(getSingletonKvKey());
      },
    ),
  ],
]);
// Append after the PINNED CCF 7.0.15 default actions.js in the constitution.
// These actions run only after the consortium's normal proposal resolution.
// No action accepts or writes private signing keys or plaintext TSIG secrets.
const adnsLifecycle = "public:agentdns.lifecycle";
// CCF governance may write application maps but cannot read them. Keep
// governance-owned mirrors for proposal checks; update both atomically.
const adnsGovGrants = "public:ccf.gov.agentdns.grants";
const adnsGovConfig = "public:ccf.gov.agentdns.configuration";
const adnsGovZones = "public:ccf.gov.agentdns.zones";
const adnsGovTransfer = "public:ccf.gov.agentdns.transfers";
const adnsGovPolicies = "public:ccf.gov.agentdns.policy_identities";
function adnsObject(value, fields) {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new Error("expected object");
  const actual = Object.keys(value).sort(), expected = [...fields].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("unknown or missing field");
}
function adnsInteger(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error("integer outside range");
}
function adnsString(value, maximum = 512) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\x00-\x20\x7f]/.test(value)) throw new Error("invalid string");
}
function adnsName(value, underscore = false) {
  adnsString(value, 254);
  if (!value.endsWith(".") || value === ".") throw new Error("absolute name required");
  for (const label of value.slice(0, -1).split(".")) {
    if (label.length < 1 || label.length > 63 || !(underscore ? /^[a-z0-9_-]+$/ : /^[a-z0-9-]+$/).test(label) || label.startsWith("-") || label.endsWith("-")) throw new Error("canonical ASCII name required");
  }
}
function adnsHex(value) { if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error("SHA-256 lowercase hex required"); }
function adnsArray(value, validator, maximum = 512) {
  if (!Array.isArray(value) || value.length > maximum || new Set(value.map(JSON.stringify)).size !== value.length) throw new Error("bounded distinct array required");
  value.forEach(validator);
}
function adnsWireName(name) {
  adnsName(name);
  const bytes = [];
  for (const label of name.slice(0, -1).split(".")) {bytes.push(label.length);for (const char of label) bytes.push(char.charCodeAt(0));}
  bytes.push(0);return new Uint8Array(bytes).buffer;
}
function adnsWrite(table, key, value) {ccf.kv[table].set(key, ccf.jsonCompatibleToBuf(value));}
// Exact JSON identity: object order is irrelevant; array order and every
// explicit field remain significant. Bounds apply before recursion/encoding.
function adnsPolicyIdentity(policy) {
  const fields=["policy_id","release_id","active_profiles","valid_from","valid_until","max_appraisal_lifetime","minimum_tcb","approved_measurements","approved_host_data","uvm"];
  adnsObject(policy,Object.prototype.hasOwnProperty.call(policy || {},"uvm_endorsement_time_policy") ? [...fields,"uvm_endorsement_time_policy"] : fields);
  if(!Array.isArray(policy.policy_id)||policy.policy_id.length!==32)throw new Error("policy_id must contain 32 bytes");
  policy.policy_id.forEach(v=>adnsInteger(v,0,255));
  if(policy.policy_id.every(v=>v===0))throw new Error("nonzero policy_id required");
  let nodes=0, bytes=0;
  function account(encoded) {
    bytes+=ccf.strToBuf(encoded).byteLength;
    if(bytes>65536)throw new Error("policy exceeds 64 KiB");
    return encoded;
  }
  function canonical(value,depth) {
    if(++nodes>4096||depth>8)throw new Error("policy structure exceeds bounds");
    if(value===null||typeof value==="boolean")return account(JSON.stringify(value));
    if(typeof value==="number"){adnsInteger(value);if(Object.is(value,-0))throw new Error("negative zero not allowed");return account(JSON.stringify(value));}
    if(typeof value==="string") {
      if(value.length>65536)throw new Error("policy string exceeds bounds");
      for(let i=0;i<value.length;i++) {
        const c=value.charCodeAt(i);
        if(c>=0xd800&&c<=0xdbff){const next=value.charCodeAt(++i);if(!(next>=0xdc00&&next<=0xdfff))throw new Error("invalid Unicode string");}
        else if(c>=0xdc00&&c<=0xdfff)throw new Error("invalid Unicode string");
      }
      return account(JSON.stringify(value));
    }
    if(Array.isArray(value)){if(value.length>4096)throw new Error("policy array exceeds bounds");account("[]"+",".repeat(Math.max(0,value.length-1)));return "["+value.map(v=>canonical(v,depth+1)).join(",")+"]";}
    if(typeof value==="object") {
      const keys=Object.keys(value).sort();
      if(keys.length>4096)throw new Error("policy object exceeds bounds");
      account("{}"+":".repeat(keys.length)+",".repeat(Math.max(0,keys.length-1)));
      return "{"+keys.map(k=>canonical(k,depth+1)+":"+canonical(value[k],depth+1)).join(",")+"}";
    }
    throw new Error("non-JSON policy value");
  }
  const encoded=canonical(policy,0);
  if(ccf.strToBuf(encoded).byteLength>65536)throw new Error("policy exceeds 64 KiB");
  return {key:ccf.strToBuf(policy.policy_id.map(v=>v.toString(16).padStart(2,"0")).join("")),canonical:encoded};
}
function adnsGrant(grant) {
  // attested_names/attested_record_types (attested-path TXT such as DKIM and
  // receipt keys) and the "anchor" operation were added for the agent-hosting
  // shared interface. Grants committed before then deserialize with empty lists.
  adnsObject(grant,["grant_id","subject_spki_sha256","zones","mailbox_domains","service_hosts","roles","address_cidrs","ports","allowed_operations","acme_names","operator_names","operator_record_types","attested_names","attested_record_types","max_lease_seconds","max_challenge_lifetime_seconds","valid_from","valid_until","revoked"]);
  adnsString(grant.grant_id,128);adnsHex(grant.subject_spki_sha256);
  for (const key of ["zones","mailbox_domains","service_hosts","acme_names"]) adnsArray(grant[key],v=>adnsName(v));
  adnsArray(grant.operator_names,v=>adnsName(v,true));
  adnsArray(grant.attested_names,v=>adnsName(v,true));
  for (const key of ["roles","address_cidrs"]) adnsArray(grant[key],v=>adnsString(v,128));
  adnsArray(grant.ports,v=>adnsInteger(v,1,65535),128);
  if (grant.ports.some((v,i)=>i>0 && grant.ports[i-1]>=v)) throw new Error("ports must be sorted");
  const operations=["register","renew","deregister","acme_challenge_create","acme_challenge_delete","operator_records","anchor"];
  adnsArray(grant.allowed_operations,v=>{if(!operations.includes(v))throw new Error("unknown operation");});
  adnsArray(grant.operator_record_types,v=>{if(!["A","AAAA","NS","CNAME","MX","TXT","CAA"].includes(v))throw new Error("unknown operator type");});
  adnsArray(grant.attested_record_types,v=>{if(!["TXT"].includes(v))throw new Error("unknown attested type");});
  if((grant.attested_names.length>0)!==(grant.attested_record_types.length>0))throw new Error("attested names and types go together");
  for (const key of ["max_lease_seconds","max_challenge_lifetime_seconds"]) adnsInteger(grant[key],1);
  adnsInteger(grant.valid_from);adnsInteger(grant.valid_until,grant.valid_from+1);
  if(typeof grant.revoked!=="boolean" || grant.zones.length===0 || grant.allowed_operations.length===0)throw new Error("invalid grant");
}
actions.set("adns_set_owner_grant", new Action(
  args=>{adnsObject(args,["grant"]);adnsGrant(args.grant);},
  args=>{const key=ccf.strToBuf(args.grant.grant_id);adnsWrite(adnsGovGrants,key,args.grant);adnsWrite("public:agentdns.grants",key,args.grant);}
));
actions.set("adns_revoke_owner_grant", new Action(
  args=>{adnsObject(args,["grant_id"]);adnsString(args.grant_id,128);},
  args=>{const key=ccf.strToBuf(args.grant_id), old=ccf.kv[adnsGovGrants].get(key);if(old===undefined)throw new Error("grant missing");const grant=ccf.bufToJsonCompatible(old);grant.revoked=true;adnsWrite(adnsGovGrants,key,grant);adnsWrite("public:agentdns.grants",key,grant);}
));
actions.set("adns_set_configuration", new Action(
  args=>{adnsObject(args,["audience","epoch","last_time"]);adnsString(args.audience);adnsInteger(args.epoch,1);adnsInteger(args.last_time);},
  args=>{const key=ccf.strToBuf("configuration"),old=ccf.kv[adnsGovConfig].get(key);if(old!==undefined){const config=ccf.bufToJsonCompatible(old);if(args.epoch<=config.epoch)throw new Error("configuration epoch must advance");}adnsWrite(adnsGovConfig,key,args);adnsWrite(adnsLifecycle,ccf.strToBuf("governance/configuration"),args);}
));
// ---- Release authority D and signed policy changes (shared interface items 1, 9) ----
const adnsGovReleaseAuthority = "public:ccf.gov.agentdns.release_authority";
const adnsGovNodeJoinPolicy = "public:ccf.gov.agentdns.node_join_policy";
function adnsBase64Url(value, maximum) {
  adnsString(value, maximum);
  if(!/^[A-Za-z0-9_-]+$/.test(value)||value.length%4===1)throw new Error("base64url required");
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const out=[];let bits=0,acc=0;
  for(const c of value){acc=(acc<<6)|alphabet.indexOf(c);bits+=6;if(bits>=8){bits-=8;out.push((acc>>bits)&0xff);}}
  if(acc&((1<<bits)-1))throw new Error("noncanonical base64url");
  return new Uint8Array(out).buffer;
}
function adnsHexOf(buffer){return Array.from(new Uint8Array(buffer)).map(b=>b.toString(16).padStart(2,"0")).join("");}
// Fixed 64-byte r||s (the same convention as service request signatures)
// converted to DER for ccf.crypto.verifySignature.
function adnsEcdsaDer(raw) {
  const bytes=new Uint8Array(raw);
  if(bytes.length!==64)throw new Error("fixed-width P-256 signature required");
  const integer=part=>{let i=0;while(i<part.length-1&&part[i]===0)i++;let body=Array.from(part.slice(i));if(body[0]&0x80)body=[0,...body];return [0x02,body.length,...body];};
  const r=integer(bytes.slice(0,32)), s=integer(bytes.slice(32));
  return new Uint8Array([0x30,r.length+s.length,...r,...s]).buffer;
}
// JCS-equivalent canonical JSON for bounded values of strings, safe integers,
// booleans, null, arrays and objects (the same value space adnsPolicyIdentity accepts).
function adnsCanonical(value) {
  let nodes=0;
  function canonical(v,depth){
    if(++nodes>4096||depth>8)throw new Error("structure exceeds bounds");
    if(v===null||typeof v==="boolean")return JSON.stringify(v);
    if(typeof v==="number"){adnsInteger(v);return JSON.stringify(v);}
    if(typeof v==="string"){if(v.length>65536)throw new Error("string exceeds bounds");return JSON.stringify(v);}
    if(Array.isArray(v)){if(v.length>4096)throw new Error("array exceeds bounds");return "["+v.map(x=>canonical(x,depth+1)).join(",")+"]";}
    if(typeof v==="object"){const keys=Object.keys(v).sort();return "{"+keys.map(k=>JSON.stringify(k)+":"+canonical(v[k],depth+1)).join(",")+"}";}
    throw new Error("non-JSON value");
  }
  return canonical(value,0);
}
function adnsReleaseAuthority() {
  const raw=ccf.kv[adnsGovReleaseAuthority].get(ccf.strToBuf("release-authority"));
  return raw===undefined?undefined:ccf.bufToJsonCompatible(raw);
}
// A change signed by D: `signature` is {did, svn, signature} over the canonical
// JSON of {"svn":svn,"payload":payload}. svn must equal the authority's current
// svn or advance it by exactly one (anti-rollback, no skipping).
function adnsRequireAuthoritySignature(payload, signature, purpose) {
  const authority=adnsReleaseAuthority();
  if(authority===undefined)throw new Error("release authority not set; "+purpose+" requires a governed release authority");
  adnsObject(signature,["did","svn","signature"]);
  if(signature.did!==authority.did)throw new Error("signature DID differs from the governed release authority");
  adnsInteger(signature.svn,authority.svn,authority.svn+1);
  const message=ccf.strToBuf(adnsCanonical({svn:signature.svn,payload}));
  const der=adnsEcdsaDer(adnsBase64Url(signature.signature,128));
  if(!ccf.crypto.verifySignature({name:"ECDSA",hash:"SHA-256"},authority.public_key_pem,der,message))throw new Error("release authority signature invalid for "+purpose);
  if(signature.svn>authority.svn){
    // The authority record's svn is the high-water mark of everything D has signed.
    const ratcheted={...authority,svn:signature.svn};
    adnsWrite(adnsGovReleaseAuthority,ccf.strToBuf("release-authority"),ratcheted);
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/release-authority"),ratcheted);
  }
  return signature.svn;
}
actions.set("adns_set_release_authority", new Action(
  args=>{
    adnsObject(args,["authority"]);
    adnsObject(args.authority,["did","public_key_pem","svn","valid_from","valid_until"]);
    adnsString(args.authority.did,512);
    if(!/^did:x509:0:sha256:[A-Za-z0-9_-]+::/.test(args.authority.did))throw new Error("did:x509 required");
    if(typeof args.authority.public_key_pem!=="string"||!/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?$/.test(args.authority.public_key_pem)||args.authority.public_key_pem.length>2048)throw new Error("SPKI PEM required");
    adnsInteger(args.authority.svn,0);adnsInteger(args.authority.valid_from);adnsInteger(args.authority.valid_until,args.authority.valid_from+1);
  },
  (args,proposalId)=>{
    const key=ccf.strToBuf("release-authority"), old=adnsReleaseAuthority();
    // Rotation never lowers the SVN floor; a new key starts where the old one stopped.
    if(old!==undefined && args.authority.svn<old.svn)throw new Error("release authority svn cannot regress");
    adnsWrite(adnsGovReleaseAuthority,key,args.authority);
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/release-authority"),args.authority);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
// Replaces ad-hoc add_snp_measurement/add_snp_host_data/add_snp_uvm_endorsement
// for primary upgrades: one signed, SVN-ratcheted policy that SETS the exact
// node join tables (removing anything not listed), so a retired release cannot
// rejoin and the accepted set is always what D last signed.
function adnsNodeJoinPolicy(policy) {
  adnsObject(policy,["svn","release_id","measurements","host_data","uvm_endorsements","tcb_versions"]);
  adnsInteger(policy.svn,1);adnsString(policy.release_id,128);
  adnsArray(policy.measurements,v=>{if(typeof v!=="string"||!/^[0-9a-f]{96}$/.test(v))throw new Error("SNP measurement hex required");},64);
  adnsArray(policy.host_data,v=>{adnsHex(v);},64);
  adnsArray(policy.uvm_endorsements,v=>{adnsObject(v,["did","feed","svn"]);adnsString(v.did,512);adnsString(v.feed,128);adnsString(v.svn,16);if(!/^[0-9]+$/.test(v.svn))throw new Error("uvm svn digits");},64);
  if(policy.measurements.length===0||policy.host_data.length===0||policy.uvm_endorsements.length===0)throw new Error("node join policy must list measurements, host data and UVM endorsements");
  adnsObject(policy.tcb_versions,Object.keys(policy.tcb_versions));
  const cpuids=Object.keys(policy.tcb_versions);
  if(cpuids.length===0||cpuids.length>16)throw new Error("tcb_versions per cpuid required");
  for(const cpuid of cpuids){adnsString(cpuid,64);adnsObject(policy.tcb_versions[cpuid],["boot_loader","tee","snp","microcode"]);for(const f of ["boot_loader","tee","snp","microcode"])adnsInteger(policy.tcb_versions[cpuid][f],0,255);}
}
actions.set("adns_set_node_join_policy", new Action(
  args=>{adnsObject(args,["policy","signature"]);adnsNodeJoinPolicy(args.policy);adnsObject(args.signature,["did","svn","signature"]);},
  (args,proposalId)=>{
    const key=ccf.strToBuf("node-join-policy"), raw=ccf.kv[adnsGovNodeJoinPolicy].get(key);
    const current=raw===undefined?undefined:ccf.bufToJsonCompatible(raw);
    if(current!==undefined && args.policy.svn<=current.svn)throw new Error("node join policy svn must advance (anti-rollback)");
    const svn=adnsRequireAuthoritySignature(args.policy,args.signature,"node join policy");
    if(svn!==args.policy.svn)throw new Error("signature svn must equal policy svn");
    // SET semantics on CCF's own join tables.
    const measurements=ccf.kv["public:ccf.gov.nodes.snp.measurements"], hostData=ccf.kv["public:ccf.gov.nodes.snp.host_data"], uvm=ccf.kv["public:ccf.gov.nodes.snp.uvm_endorsements"], tcb=ccf.kv["public:ccf.gov.nodes.snp.tcb_versions"];
    for(const table of [measurements,hostData,uvm,tcb]) if(typeof table.clear==="function") table.clear(); else table.forEach((_,k)=>table.delete(k));
    for(const m of args.policy.measurements) measurements.set(ccf.strToBuf(m),ccf.jsonCompatibleToBuf("AllowedToJoin"));
    for(const h of args.policy.host_data) hostData.set(ccf.strToBuf(h),ccf.jsonCompatibleToBuf(""));
    const byDid={};
    for(const e of args.policy.uvm_endorsements){byDid[e.did]=byDid[e.did]||{};byDid[e.did][e.feed]={svn:e.svn};}
    for(const did of Object.keys(byDid)) uvm.set(ccf.strToBuf(did),ccf.jsonCompatibleToBuf(byDid[did]));
    for(const cpuid of Object.keys(args.policy.tcb_versions)) tcb.set(ccf.strToBuf(cpuid),ccf.jsonCompatibleToBuf(args.policy.tcb_versions[cpuid]));
    const record={...args.policy,policy_sha256:adnsHexOf(ccf.crypto.digest("SHA-256",ccf.strToBuf(adnsCanonical(args.policy)))),signed_by:args.signature.did};
    adnsWrite(adnsGovNodeJoinPolicy,key,record);
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/node-join-policy"),record);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
actions.set("adns_set_appraisal_policy", new Action(
  args=>{
    const fields=Object.prototype.hasOwnProperty.call(args||{},"signature")?["zone","policy","signature"]:["zone","policy"];
    adnsObject(args,fields);adnsName(args.zone);adnsPolicyIdentity(args.policy);
    if(fields.length===3)adnsObject(args.signature,["did","svn","signature"]);
  },
  (args,proposalId)=>{
    const identity=adnsPolicyIdentity(args.policy), old=ccf.kv[adnsGovPolicies].get(identity.key);
    if(old!==undefined && ccf.bufToJsonCompatible(old).canonical!==identity.canonical)throw new Error("policy contents changed; use a new policy_id");
    if(old===undefined && ccf.kv[adnsGovPolicies].size>=512)throw new Error("maximum 512 immutable appraisal policy identities");
    // Once a release authority is governed, every workload policy must carry
    // its signature; unsigned policies were the pre-D bootstrap path only.
    if(adnsReleaseAuthority()!==undefined){
      if(args.signature===undefined)throw new Error("appraisal policy requires the release authority signature");
      adnsRequireAuthoritySignature(args.policy,args.signature,"appraisal policy");
    }
    adnsWrite(adnsGovPolicies,identity.key,{canonical:identity.canonical});
    adnsWrite("public:agentdns.policies",adnsWireName(args.zone),args.policy);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
actions.set("adns_create_zone", new Action(
  args=>{adnsObject(args,["metadata"]);adnsObject(args.metadata,["id","origin","serial","base_records","signed_records","signature_validity","refresh_before","last_signed_at","earliest_signature_expiration","maintenance_health","ksk_dnskey_rdata"]);adnsName(args.metadata.origin);adnsInteger(args.metadata.signature_validity,600,2147483647);adnsInteger(args.metadata.refresh_before,300,args.metadata.signature_validity-1);if(!Array.isArray(args.metadata.base_records)||args.metadata.base_records.length===0||args.metadata.base_records.length>4096)throw new Error("base records required");if(args.metadata.signed_records.length!==0||args.metadata.ksk_dnskey_rdata.length!==0)throw new Error("signing material generated in enclave only");},
  args=>{const key=adnsWireName(args.metadata.origin);if(ccf.kv[adnsGovZones].has(key))throw new Error("zone already governed");if(ccf.kv[adnsGovZones].size>=32)throw new Error("maximum 32 governed zones");adnsWrite(adnsGovZones,key,args.metadata);adnsWrite(adnsLifecycle,ccf.strToBuf("governance/zone/"+args.metadata.origin),args.metadata);}
));
actions.set("adns_set_transfer", new Action(
  args=>{adnsObject(args,["key_name","endpoint","zones","secret_sha256"]);adnsName(args.key_name);adnsString(args.endpoint,128);adnsHex(args.secret_sha256);adnsArray(args.zones,v=>adnsName(v),128);if(args.zones.length===0)throw new Error("zone scope required");},
  args=>{const key=ccf.strToBuf("governance/transfer/"+args.key_name),old=ccf.kv[adnsGovTransfer].get(key);if(old===undefined && ccf.kv[adnsGovTransfer].size>=512)throw new Error("maximum 512 governed transfer key identities");if(old!==undefined){const existing=ccf.bufToJsonCompatible(old);if(existing.revoked===true)throw new Error("transfer identity permanently revoked; use a new key_name");if(existing.secret_sha256!==args.secret_sha256 || existing.endpoint!==args.endpoint)throw new Error("new endpoint or secret requires new key_name");}adnsWrite(adnsGovTransfer,key,args);adnsWrite(adnsLifecycle,key,args);}
));
actions.set("adns_revoke_transfer", new Action(
  args=>{adnsObject(args,["key_name"]);adnsName(args.key_name);},
  args=>{const key=ccf.strToBuf("governance/transfer/"+args.key_name),old=ccf.kv[adnsGovTransfer].get(key);if(old===undefined)throw new Error("transfer identity missing");const revoked=ccf.bufToJsonCompatible(old);revoked.revoked=true;adnsWrite(adnsGovTransfer,key,revoked);adnsWrite(adnsLifecycle,key,revoked);}
));
// ---- KSK rollover (RFC 6781 double signature), governed; the app drains the command ----
// start: the enclave generates the incoming KSK and publishes/signs with both.
// complete: only with the incoming key's exact tag and DS, which the proposer
// attests are now published at the parent; the app also enforces its hold.
// abort: allowed while double-signing. The app refuses anything else.
const adnsGovKskRollover = "public:ccf.gov.agentdns.ksk_rollover";
actions.set("adns_ksk_rollover", new Action(
  args=>{
    adnsObject(args,["zone","command","new_key_tag","new_ds_sha256","minimum_hold_seconds"]);adnsName(args.zone);
    if(!["start","complete","abort"].includes(args.command))throw new Error("command start|complete|abort");
    if(args.command==="complete"){adnsInteger(args.new_key_tag,0,65535);adnsHex(args.new_ds_sha256);}
    else if(args.new_key_tag!==null||args.new_ds_sha256!==null)throw new Error("tag and DS only with complete");
    if(args.minimum_hold_seconds!==null)adnsInteger(args.minimum_hold_seconds,600,30*86400);
    if(args.command!=="start"&&args.minimum_hold_seconds!==null)throw new Error("hold only with start");
  },
  (args,proposalId)=>{
    const key=ccf.strToBuf(args.zone), raw=ccf.kv[adnsGovKskRollover].get(key);
    const state=raw===undefined?{stage:"idle"}:ccf.bufToJsonCompatible(raw);
    if(args.command==="start"&&state.stage!=="idle")throw new Error("rollover already in progress");
    if(args.command!=="start"&&state.stage!=="double-signature")throw new Error("no rollover in progress");
    const next=args.command==="start"?{stage:"double-signature",started_in:proposalId}:{stage:"idle",last:args.command,proposal:proposalId};
    adnsWrite(adnsGovKskRollover,key,next);
    const command={zone:args.zone,command:args.command,new_key_tag:args.new_key_tag,new_ds_sha256:args.new_ds_sha256,minimum_hold_seconds:args.minimum_hold_seconds};
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/ksk-rollover/"+args.zone),command);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
// ---- Governors: open-join, reputation-weighted, agent-led, with a human trap door ----
// Shape (agent-hosting ADR 0025 / agentdns ADR 0002): members are verifier agents
// (class "agent") or humans (class "trapdoor"). Votes are weighted by reputation,
// earned by verdicts that agree with outcomes and lost by verdicts that do not.
// A `block` verdict (a BountyNet-style finding) holds a release proposal open until
// withdrawn. A trapdoor vote is decisive either way and is loud in the ledger.
const adnsGovGovernors = "public:ccf.gov.agentdns.governors";
const adnsGovVerdicts = "public:ccf.gov.agentdns.verdicts";
const adnsGovSettled = "public:ccf.gov.agentdns.settled";
const adnsGovParams = "public:ccf.gov.agentdns.governance";
const adnsHighImpact = ["set_constitution","set_js_app","set_member","remove_member","set_recovery_threshold","transition_service_to_open",
  "add_snp_measurement","add_snp_host_data","add_snp_uvm_endorsement","set_snp_minimum_tcb_version","set_snp_minimum_tcb_version_hex",
  "remove_snp_measurement","remove_snp_host_data","remove_snp_uvm_endorsement","remove_snp_minimum_tcb_version",
  "adns_set_node_join_policy","adns_set_appraisal_policy","adns_set_release_authority","adns_set_governance_parameters","adns_set_governor","adns_ksk_rollover"];
function adnsDefaultParams() {
  return {release_threshold:[2,3],block_threshold:[1,3],routine_threshold:[1,2],min_agent_yes:1,newcomer_weight_cap_percent:20,
    max_member_weight_percent:34,reputation_min:1,reputation_max:64,reputation_step:1,block_reputation:2,open_join:true,high_impact_actions:adnsHighImpact};
}
function adnsParams() {
  const raw=ccf.kv[adnsGovParams].get(ccf.strToBuf("parameters"));
  return raw===undefined?adnsDefaultParams():{...adnsDefaultParams(),...ccf.bufToJsonCompatible(raw)};
}
function adnsGovernorOf(memberId, params) {
  const raw=ccf.kv[adnsGovGovernors].get(ccf.strToBuf(memberId));
  return raw===undefined?{class:"agent",reputation:params.reputation_min,joined_via:"unregistered"}:ccf.bufToJsonCompatible(raw);
}
function adnsText(value, maximum) { if (typeof value !== "string" || value.length > maximum || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) throw new Error("invalid text"); }
function adnsRatio(value) { if(!Array.isArray(value)||value.length!==2)throw new Error("ratio [num,den] required");adnsInteger(value[0],0,1000);adnsInteger(value[1],1,1000);if(value[0]>value[1])throw new Error("ratio above one"); }
actions.set("adns_set_governance_parameters", new Action(
  args=>{
    adnsObject(args,["parameters"]);
    const p=args.parameters, keys=Object.keys(adnsDefaultParams());
    adnsObject(p,Object.keys(p).filter(k=>keys.includes(k)));
    for(const k of ["release_threshold","block_threshold","routine_threshold"]) if(k in p) adnsRatio(p[k]);
    if("min_agent_yes" in p) adnsInteger(p.min_agent_yes,1,64);
    for(const k of ["newcomer_weight_cap_percent","max_member_weight_percent"]) if(k in p) adnsInteger(p[k],1,100);
    for(const k of ["reputation_min","reputation_max","reputation_step","block_reputation"]) if(k in p) adnsInteger(p[k],1,1000000);
    if("reputation_min" in p && "reputation_max" in p && p.reputation_min>p.reputation_max) throw new Error("reputation bounds");
    if("open_join" in p && typeof p.open_join!=="boolean") throw new Error("open_join boolean");
    if("high_impact_actions" in p) adnsArray(p.high_impact_actions,v=>adnsString(v,128),128);
  },
  (args,proposalId)=>{adnsWrite(adnsGovParams,ccf.strToBuf("parameters"),{...adnsParams(),...args.parameters});adnsWrite(adnsLifecycle,ccf.strToBuf("governance/parameters"),{...adnsParams(),...args.parameters});if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);}
));
// Register or reclassify a member as a governor. Open join: any member may be
// proposed by any member; admission is decided by the weighted vote like any
// other high-impact proposal. Reputation is set only at registration (to the
// minimum unless a trapdoor is being registered) and thereafter only by settle.
actions.set("adns_set_governor", new Action(
  args=>{
    adnsObject(args,["member_id","class","note"]);adnsString(args.member_id,64);
    if(!/^[0-9a-f]{64}$/.test(args.member_id))throw new Error("member_id is a 64-hex CCF member id");
    if(!["agent","trapdoor"].includes(args.class))throw new Error("class agent|trapdoor");adnsText(args.note,512);
  },
  (args,proposalId)=>{
    const params=adnsParams(), key=ccf.strToBuf(args.member_id), old=ccf.kv[adnsGovGovernors].get(key);
    const existing=old===undefined?undefined:ccf.bufToJsonCompatible(old);
    const record={class:args.class,reputation:existing?existing.reputation:params.reputation_min,joined_via:existing?existing.joined_via:proposalId,note:args.note};
    adnsWrite(adnsGovGovernors,key,record);adnsWrite(adnsLifecycle,ccf.strToBuf("governance/governor/"+args.member_id),record);
    if(typeof invalidateOtherOpenProposals==="function")invalidateOtherOpenProposals(proposalId);
  }
));
// A verdict is a self-attesting statement by the proposing member about another
// proposal: approve, block (a finding), or withdraw (of its own block). It is
// accepted by resolve() on the proposer's word alone because it only writes the
// verdict table; its effect on the target proposal comes through resolve().
actions.set("adns_record_verdict", new Action(
  args=>{
    adnsObject(args,["proposal_id","verdict","checks","evidence","rationale"]);
    if(!/^[0-9a-f]{64}$/.test(args.proposal_id))throw new Error("proposal_id is a 64-hex CCF proposal id");
    if(!["approve","block","withdraw"].includes(args.verdict))throw new Error("verdict approve|block|withdraw");
    adnsArray(args.checks,c=>{adnsObject(c,["name","passed","detail"]);adnsString(c.name,64);if(typeof c.passed!=="boolean")throw new Error("passed boolean");adnsText(c.detail,1024);},64);
    if(args.verdict==="block" && !args.checks.some(c=>c.passed===false))throw new Error("a block verdict needs at least one failed check");
    adnsObject(args.evidence,Object.keys(args.evidence));for(const k of Object.keys(args.evidence)){adnsString(k,64);adnsText(args.evidence[k],4096);}
    if(Object.keys(args.evidence).length>32)throw new Error("evidence keys");adnsText(args.rationale,4096);
  },
  (args,proposalId)=>{
    const raw=ccf.kv["public:ccf.gov.proposals_info"].get(ccf.strToBuf(proposalId));
    if(raw===undefined)throw new Error("verdict proposal has no info");
    const proposer=ccf.bufToJsonCompatible(raw).proposer_id;
    const record={...args,by:proposer,in_proposal:proposalId};
    adnsWrite(adnsGovVerdicts,ccf.strToBuf(args.proposal_id+"/"+proposer),record);
    adnsWrite(adnsLifecycle,ccf.strToBuf("governance/verdict/"+args.proposal_id+"/"+proposer),record);
  }
));
// Settle reputation for a resolved proposal, once: voters on the winning side gain
// a step, voters on the losing side lose a step, within [min, max]. Any member may
// propose settlement; the ledger's own final_votes are the only input.
actions.set("adns_settle", new Action(
  args=>{adnsObject(args,["proposal_id"]);if(!/^[0-9a-f]{64}$/.test(args.proposal_id))throw new Error("proposal_id is a 64-hex CCF proposal id");},
  (args,proposalId)=>{
    const key=ccf.strToBuf(args.proposal_id);
    if(ccf.kv[adnsGovSettled].has(key))throw new Error("already settled");
    const raw=ccf.kv["public:ccf.gov.proposals_info"].get(key);
    if(raw===undefined)throw new Error("unknown proposal");
    const info=ccf.bufToJsonCompatible(raw);
    if(!["Accepted","Rejected"].includes(info.state))throw new Error("proposal not resolved");
    const params=adnsParams(), winning=info.state==="Accepted", changes={};
    for(const [memberId,vote] of Object.entries(info.final_votes||{})) {
      const g=adnsGovernorOf(memberId,params);
      if(g.class!=="agent")continue;
      const delta=(vote===winning)?params.reputation_step:-params.reputation_step;
      const next=Math.max(params.reputation_min,Math.min(params.reputation_max,g.reputation+delta));
      if(next!==g.reputation){changes[memberId]=[g.reputation,next];adnsWrite(adnsGovGovernors,ccf.strToBuf(memberId),{...g,reputation:next});}
    }
    const record={state:info.state,changes,settled_in:proposalId};
    adnsWrite(adnsGovSettled,key,record);adnsWrite(adnsLifecycle,ccf.strToBuf("governance/settled/"+args.proposal_id),record);
  }
));
export function validate(input) {
  let proposal = JSON.parse(input);
  let errors = [];
  let position = 0;
  for (const action of proposal["actions"]) {
    const definition = actions.get(action.name);
    if (definition) {
      try {
        definition.validate(action.args);
      } catch (e) {
        errors.push(
          `${action.name} at position ${position} failed validation: ${e}\n${e.stack}`,
        );
      }
    } else {
      errors.push(`${action.name}: no such action`);
    }
    position++;
  }
  return { valid: errors.length === 0, description: errors.join(", ") };
}
export function apply(proposal, proposalId) {
  const proposed_actions = JSON.parse(proposal)["actions"];
  for (const proposed_action of proposed_actions) {
    const definition = actions.get(proposed_action.name);
    definition.apply(proposed_action.args, proposalId);
  }
}
// resolve(): the vote rule of the agent.hosting/agentdns governance (replaces the
// CCF sandbox "accept everything"). Reads only governance tables.
//
//  1. A proposal consisting solely of adns_record_verdict actions is a statement by
//     its proposer and is Accepted immediately (it writes only the verdict table).
//  2. A trapdoor member's vote is decisive: false = veto (Rejected), true = override
//     (Accepted). Both are ordinary ballots, visible in the ledger.
//  3. Otherwise agents decide by reputation-weighted vote. Weights are capped per
//     member and for newcomers once the consortium has three or more agents, so
//     neither one veteran nor a flood of fresh joiners can carry a decision alone.
//  4. High-impact proposals need yes >= 2/3 of total weight and at least
//     min_agent_yes distinct agents; they are Rejected once no >= 1/3. Routine
//     proposals need a strict majority.
//  5. An unwithdrawn `block` verdict from an agent with enough reputation holds a
//     high-impact proposal Open regardless of yes-weight (the finding mechanism).
export function resolve(proposal, proposerId, votes) {
  const params = adnsParams();
  const actionsIn = JSON.parse(proposal).actions.map(a => a.name);
  if (actionsIn.length > 0 && actionsIn.every(n => n === "adns_record_verdict")) return "Accepted";
  const highImpact = actionsIn.some(n => params.high_impact_actions.includes(n));
  const active = [];
  ccf.kv["public:ccf.gov.members.info"].forEach((v, k) => {
    if (ccf.bufToJsonCompatible(v).status === "Active") active.push(ccf.bufToStr(k));
  });
  const governor = id => adnsGovernorOf(id, params);
  for (const v of votes) {
    if (!active.includes(v.member_id)) continue;
    if (governor(v.member_id).class === "trapdoor") {
      if (v.vote === false) return "Rejected";
      if (v.vote === true) return "Accepted";
    }
  }
  if (highImpact) {
    let blocked = false;
    ccf.kv[adnsGovVerdicts].forEach((v, k) => {
      const key = ccf.bufToStr(k);
      if (!key.startsWith(proposalIdForVotes(votes, proposal) + "/")) return;
      const verdict = ccf.bufToJsonCompatible(v);
      if (verdict.verdict === "block" && active.includes(verdict.by) && governor(verdict.by).reputation >= params.block_reputation) blocked = true;
    });
    if (blocked) return "Open";
  }
  const agents = active.filter(id => governor(id).class === "agent");
  const rawWeight = Object.fromEntries(agents.map(id => [id, governor(id).reputation]));
  let total = Object.values(rawWeight).reduce((a, b) => a + b, 0);
  const weight = { ...rawWeight };
  if (agents.length >= 3) {
    // Per-member cap, relative to the capped total (iterate to a fixed point so a
    // dominant member cannot exceed the percentage of what is actually counted).
    for (let round = 0; round < 12; round++) {
      const subtotal = Object.values(weight).reduce((a, b) => a + b, 0);
      const cap = Math.max(1, Math.floor(subtotal * params.max_member_weight_percent / 100));
      let changed = false;
      for (const id of agents) if (weight[id] > cap) { weight[id] = cap; changed = true; }
      if (!changed) break;
    }
    // Newcomer cap: members at minimum reputation collectively.
    const newcomers = agents.filter(id => governor(id).reputation === params.reputation_min);
    const newcomerTotal = newcomers.reduce((a, id) => a + weight[id], 0);
    const subtotal = Object.values(weight).reduce((a, b) => a + b, 0);
    const newcomerCap = Math.floor(subtotal * params.newcomer_weight_cap_percent / 100);
    if (newcomerTotal > newcomerCap && newcomers.length > 0) {
      const scaled = Math.max(0, Math.floor(newcomerCap / newcomers.length));
      for (const id of newcomers) weight[id] = scaled;
    }
    total = Object.values(weight).reduce((a, b) => a + b, 0);
  }
  if (total === 0) return "Open";
  let yes = 0, no = 0, yesCount = 0;
  for (const v of votes) {
    if (!(v.member_id in weight)) continue;
    if (v.vote) { yes += weight[v.member_id]; yesCount++; } else no += weight[v.member_id];
  }
  if (highImpact) {
    const [bn, bd] = params.block_threshold, [rn, rd] = params.release_threshold;
    if (no * bd >= total * bn) return "Rejected";
    if (yes * rd >= total * rn && yesCount >= params.min_agent_yes) return "Accepted";
    return "Open";
  }
  const [n, d] = params.routine_threshold;
  if (no * d >= total * n) return "Rejected";
  if (yes * d > total * n && yesCount >= 1) return "Accepted";
  return "Open";
}
// CCF passes the proposal text, not its id, to resolve(). Verdicts are keyed by the
// target proposal id, so recover it from proposals_info: the Open proposal whose
// recorded ballots match the member ids voting here and whose text matches.
function proposalIdForVotes(votes, proposal) {
  let found = "";
  ccf.kv["public:ccf.gov.proposals"].forEach((v, k) => {
    if (found) return;
    if (ccf.bufToStr(v) === proposal) found = ccf.bufToStr(k);
  });
  return found;
}
