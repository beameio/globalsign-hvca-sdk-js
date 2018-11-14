'use strict';

const apiEndpoint ="https://emea.api.hvca.globalsign.com:8443";

const assert = require("assert");
const util = require('util');

const rp = require("request-promise");
const dns = require("dns");
const NodeRSA = require("node-rsa");
const constants = require('constants');

const API_CALL_ATTEMPTS = Number.parseInt(process.env.GS_CLIENT_API_CALL_ATTEMPTS) || 10;
const API_CALL_SLEEP = Number.parseInt(process.env.GS_CLIENT_API_CALL_RETRY_SLEEP) || 1000;

const CERT_ATTEMPTS = Number.parseInt(process.env.GS_CLIENT_CERT_ATTEMPTS) || 10;
const CERT_SLEEP = Number.parseInt(process.env.GS_CLIENT_CERT_RETRY_SLEEP) || 1000;

const DNS_MODULE = process.env.GS_CLIENT_DNS_MODULE || './dns/route53';
const DNS_ATTEMPTS = Number.parseInt(process.env.GS_CLIENT_DNS_ATTEMPTS) || 30;
const DNS_SLEEP = Number.parseInt(process.env.GS_CLIENT_DNS_RETRY_SLEEP) || 2000;

const CLAIM_ATTEMPTS = Number.parseInt(process.env.GS_CLAIM_ATTEMPTS) || 10;
const CLAIM_SLEEP = Number.parseInt(process.env.GS_CLAIM_RETRY_SLEEP) || 10000;

const ACCESS_TOKEN_TTL = Number.parseInt(process.env.GS_ACCESS_TOKEN_TTL) || 600;

const log_debug = require('debug')('gs-client:debug');
const log_update = require('debug')('gs-client:update');

/*
    subject_dn example from documentation
    {
      "common_name": "John Doe",
      "country": "GB",
      "state": "London",
      "locality": "London",
      "street_address": "1 GlobalSign Road",
      "organization": "GMO GlobalSign",
      "organizational_unit": [
        "Operations",
        "Development"
      ],
      "email": "john.doe@demo.hvca.globalsign.com",
      "jurisdiction_of_incorporation_locality_name": "London",
      "jurisdiction_of_incorporation_state_or_province_name": "London",
      "jurisdiction_of_incorporation_country_name": "United Kingdom",
      "business_category": "Internet security",
      "extra_attributes": [
        {
          "type": "2.5.4.4",
          "value": "Surname"
        }
      ]
    }
*/

/**
 * @typedef {String} X509CertificatePEM
 * @typedef {String} PublicKeyPEM
 * @typedef {String} PrivateKeyPEM
 * @typedef {String} URL
 */


/**
 * @typedef {Object} GlobalSignHVCAClientCredentials. Specify either (.key and .secret) or (.decryptionPrivateKey and .encryptedCredentials)
 * @property {String} key
 * @property {String} secret
 * @property {String} decryptionPrivateKey
 * @property {String} encryptedCredentials - Buffer with Encrypted credentials as received from GlobalSign
 */

/**
 * @typedef {Object} GlobalSignHVCAMTLSCredentials
 * @property {X509CertificatePEM} gs_mtls_cert
 * @property {PrivateKeyPEM} gs_mtls_pk
 */

/**
 * @typedef {Object} SubjectDN
 * @property {String} common_name
 * @property {String} country
 * @property {String} state
 * @property {String} locality
 * @property {String} street_address
 * @property {String} organization
 * @property {String[]} organizational_unit
 * @property {String} email
 * @property {String} jurisdiction_of_incorporation_locality_name
 * @property {String} jurisdiction_of_incorporation_state_or_province_name
 * @property {String} jurisdiction_of_incorporation_country_name
 * @property {String} business_category
 * @property {Object[]} extra_attributes
 */

/**
 * @typedef {Object} ClaimAssertion
 * @property {String} token
 * @property {Number} assert_by
 */


/**
 * @typedef {String} DomainValidationClaimId
 */

/**
 * @typedef {Object} DomainValidationClaim
 * @property {number} created_at
 * @property {string} domain
 * @property {number} expires_at
 * @property {DomainValidationClaim} id
 * @property {object[]} log
 * @property {string} status
 */

/**
 * @typedef {object} GSLoginResponse
 * @property {string} access_token
 */

/**
 * Retry till callback promise is not failing
 * @param times
 * @param sleep
 * @param name
 * @param cb
 * @returns {Promise<*>}
 * @private
 */
async function _retry(times, sleep, name, cb) {
    let error = new Error("retry() exhausted");
    let result;
    let done;
    for(let i=0; i<times; i++) {
        log_debug('retry()', i+1, times, name);
        try {
            result = await cb();
            done = true;
        } catch(e) {
            error = e;
        }
        if(done) {
            log_debug('retry() finished ok', name);
            return result;
        }
        log_debug('retry() sleeping before retry', name);
        await new Promise(resolve => setTimeout(resolve, sleep));
    }
    log_debug('retry() failed', name);
    throw error;
}


/**
 * @member {string} _accessToken - GS access token
 * @member {number} _accessTokenExpiration - GS access token expiration time
 */
class GlobalSignHVCAClient {


    /**
     * Creates GlobalSignHVCAClient
     * @param {GlobalSignHVCAMTLSCredentials} mtlsCredentials
     * @param {GlobalSignHVCAClientCredentials} credentials
     */
    constructor(mtlsCredentials, credentials) {
        log_debug('Creating GlobalSignHVCAClient');
        this._mtlsCredentials = mtlsCredentials;
        this._accessToken = null;
        if(credentials.decryptionPrivateKey && credentials.encryptedCredentials) {
            this.initWithEncryptedCredentials(credentials.decryptionPrivateKey, credentials.encryptedCredentials);
            return;
        }
        if(credentials.key && credentials.secret) {
            this.initWithKeyAndSecret(credentials.key, credentials.secret);
            return;
        }
        throw new Error("GlobalSignHVCAClient() credentials argument - must provide either (.decryptionPrivateKey and .encryptedCredentials) or (.key and .secret)");
    }

    decryptPayload(payload, privateKey){
        const key = new NodeRSA();
        key.importKey(privateKey, "pkcs8-private-pem");
        key.setOptions({
            encryptionScheme: {
                scheme: 'pkcs1',
                padding: constants.RSA_NO_PADDING
            }
        });
        try {
            let decrypted = key.decrypt(payload, 'buffer');
            let parsed = decrypted.toString('utf-8').split("\n");
            let parsedValue = {};
            parsed.map(x => x.split(":")).forEach(([k, v]) => parsedValue[k] = v);
            return parsedValue;
        }
        catch(e) {
            console.error(`Decryption failed for payload ${e} ${Buffer.from(payload).toString("base64")}`);
            throw new Error(`Decryption failed for payload ${e} ${Buffer.from(payload).toString("base64")}`);
        }

    }

    /**
     *
     * @returns {Promise<boolean>} - whether login was actually done (false means the client was already logged in)
     */
    async login() {
        // TODO: For how long the token is valid? Renew token when needed.
        //       giving a bit of flexibility because not sure.

        log_debug("in login()");

        if(this._accessToken) {
            let now = Math.floor(Date.now() / 1000);
            if(this._accessTokenExpiration > now) {
                log_debug("login(): Access token not expired yet. Not logging in.");
                return false;
            }
        }

        log_update("Logging in");
        /**
         * @type {GSLoginResponse}
         */
        const response = await rp({
            method: 'POST',

            cert: Buffer.from(this._mtlsCredentials.gs_mtls_cert, 'utf8'),
            key: Buffer.from(this._mtlsCredentials.gs_mtls_pk,'utf8'),
            uri: apiEndpoint + '/v2/login',
            headers:{"Content-Type":"application/json; charset=UTF-8"},

            body: {
                api_key: this._apiKey,
                api_secret: this._apiSecret,
            },
            json: true // Automatically stringifies the body to JSON
        });

        assert.ok(response.access_token);

        /** @member {String} - GS access token */
        this._accessToken = response.access_token;

        /** @member {Number} - GS access token expiration time */
        this._accessTokenExpiration = Math.floor(Date.now() / 1000) + ACCESS_TOKEN_TTL - 10;

        return true;
    };

    initWithEncryptedCredentials(decryptionPrivateKey, encryptedCredentials) {
        throw new Error("initWithEncryptedCredentials() is not implemented yet");
    }

    initWithKeyAndSecret(key, secret) {
        this._apiKey = key;
        this._apiSecret = secret;
    }

    getValidationPolicy(){
        return this._makeAuthorizedRequest({
            method: 'GET',
            uri: apiEndpoint + "/v2/validationpolicy",
            resolveWithFullResponse: true,
            json: true
        }).then(x => x.body);
    }

    getTrustChain() {
        return this._makeAuthorizedRequest({
            method: 'GET',
            uri: apiEndpoint + "/v2/trustchain",
            resolveWithFullResponse: true,
            json: true
        }).then(x => x.body);
    }

    /**
     * Make an API call to create certificate.
     * @param {PublicKeyPEM} publicKey
     * @param {String} public_key_signature
     * @param {SubjectDN} subject_dn
     * @param certTTL Expiration date ("not_after") of the certificates in seconds from now
     * @param dns_names
     * @returns {Promise<URL>}
     */
    async createCertificate(publicKey, public_key_signature, subject_dn, certTTL, dns_names) {
        let requestBody = {
            validity: {
                not_before: Math.floor((new Date().getTime() / 1000)),
                not_after: Math.floor(certTTL + (new Date().getTime() / 1000))
            },
            subject_dn: subject_dn,
            public_key: publicKey,
        };

        if (dns_names) {
            assert.ok(Array.isArray(dns_names));
            if (dns_names.length > 0) {
                requestBody.san = {
                    dns_names: dns_names
                };
            }
        }

        if (public_key_signature) {
            requestBody.public_key_signature = public_key_signature;
        }

        log_update(`Creating certificate publicKey=%j public_key_signature=%j dn=%j`, publicKey, public_key_signature, subject_dn);
        let options = {
            method: 'POST',
            uri: apiEndpoint + "/v2/certificates",
            resolveWithFullResponse: true,
            // TODO: json: true
            body: JSON.stringify(requestBody),
            json: false, // Automatically stringifies the body to JSON
        };

        const response = await this._makeAuthorizedRequest(options);
        assert.equal(response.statusCode, 201, "HTTP status code must be 201");
        assert.ok(response.headers.location, "HTTP response must have location header");
        return apiEndpoint + response.headers.location;
    }

    async retrieveCertificate(location){
        let response = null;
        for(let retry = 0; retry <= CERT_ATTEMPTS; retry++) {
            response = await this._makeAuthorizedRequest({
                method: 'GET',
                uri: location,
                json: true
            });
            if (response.statusCode === 200) {
                return response.body.certificate;
            }
            await new Promise(resolve => setTimeout(resolve, CERT_SLEEP));
        }
        throw new Error(`retrieveCertificate() failed. Last response - ${response.statusCode} ${response.body}`);
    }

    /**
     * Make an API call to create certificate.
     * @param {PublicKeyPEM} publicKey
     * @param {String} public_key_signature
     * @param {SubjectDN} subject_dn
     * @param certTTL Expiration date ("not_after") of the certificates in seconds from now
     * @param dns_names
     * @returns {Promise<X509CertificatePEM>}
     */
    createAndRetrieveCertificate(publicKey, public_key_signature, subject_dn, certTTL, dns_names) {
        return this.createCertificate.apply(this, arguments)
            .then(this.retrieveCertificate.bind(this));
    }

    /**
     *
     * @param {string|null} domain
     * @returns {Promise<DomainValidationClaim[]>}
     */
    async listDomainValidationClaims(domain) {
        // TODO: very short-lived cache
        if (domain) {
            if(domain.endsWith(".")) {
                throw new Error(`listClaims(): domain argument must not end with dot. Given: "${domain}"`);
            }
        }
        let claims = await this._makeAuthorizedRequest({
            method: 'GET',
            uri: apiEndpoint + "/v2/claims/domains",
            json: true
        });
        claims = claims.body;
        if(!domain) {
            return claims;
        }
        return claims.filter(claim => claim.domain === domain + ".");
    }

    /**
     *
     * @param domain
     * @returns {Promise<DomainValidationClaimId>}
     */
    async createDomainValidationClaim(domain) {
        log_update(`Creating domain validation claim for domain ${domain}`);
        let response = await this._makeAuthorizedRequest({
            method: 'POST',
            uri: apiEndpoint + "/v2/claims/domains/" + domain,
            json: true
        });
        if(!response.headers.location) {
            throw new Error(`createDomainValidationClaim() no response location header`);
        }
        // Sample response.headers.location: /v2/claims/domains/014E9CEAF4D351FE5AA76E6E9B3BCDA5
        const m = response.headers.location.match(/^\/v2\/claims\/domains\/([A-Z0-9]+)$/);
        if(!m) {
            throw new Error(`createDomainValidationClaim() could not parse response location header: ${response.headers.location}`);
        }
        return m[1];
    }

    async submitValidationClaim(claimId) {
        log_update(`Submitting domain validation claim ${claimId}`);
        return this._makeAuthorizedRequest({
            method: "POST",
            uri: apiEndpoint + `/v2/claims/domains/${claimId}/dns`,
        });
    }

    /**
     * @param claimId
     */
    async assertDomainValidationClaim(claimId) {

        const checker = (claimBeforeOperation, claimAfterOperation) => {
            assert.equal(claimAfterOperation.status, "VERIFIED", "Claim must be verified");
        };

        return await this._assertDomainValidationClaim(claimId, checker);
    }

    /**
     * @param claimId
     */
    async reassertDomainValidationClaim(claimId) {

        const checker = (claimBeforeOperation, claimAfterOperation) => {
            assert.ok(claimBeforeOperation.expires_at !== claimAfterOperation.expires_at, "New claim expiration must be later");
        };

        return await this._assertDomainValidationClaim(claimId, checker);
    }

    /**
     * Retrieves DV claim
     * @param claimId
     * @returns {Promise<DomainValidationClaim>}
     */
    async getDomainValidationClaim(claimId){
        let claim = await this._makeAuthorizedRequest({
            method: "GET",
            uri: apiEndpoint + "/v2/claims/domains/" + claimId,
            json: true
        });
        return claim.body;
    }

    /**
     * Deletes DV claim
     * @param claimId
     * @returns {Promise<void>}
     */
    async deleteDomainValidationClaim(claimId){
        log_update(`Deleting domain validation claim ${claimId}`);
        await this._makeAuthorizedRequest({
            method: "DELETE",
            uri: apiEndpoint + "/v2/claims/domains/" + claimId,
        });
    }

    /**
     *
     * @returns {Promise<number>} number of deleted domains
     */
    async deleteUnverifiedDomainValidationClaims(domain) {
        assert.ok(domain, "deleteUnverifiedDomainValidationClaims() - domain is a required argument");
        // TODO: deleteUnverifiedDomainValidationClaims() implementation
        let existingClaims = await this.listDomainValidationClaims(domain);
        let claimsToDelete = existingClaims.filter(x => x.status !== "VERIFIED");
        await Promise.all(claimsToDelete.map(claim => claim.id).map(this.deleteDomainValidationClaim.bind(this)));
        return claimsToDelete.length;
    }

    async isDomainValidated(domain) {
        let existingClaims = await this.listDomainValidationClaims(domain);
        return existingClaims.some(claim => claim.status === "VERIFIED");
    }

    /**
     * Make sure the domain has non-expiring, verified domain validation claims.
     * @param {string} domain
     * @param {object} [options]
     * @param {number} [options.min_expires_at=1 week from now]
     * @returns {Promise<boolean>} whether the validation was performed (false - domain was already validated)
     */
    async ensureDomainValidation(domain, options) {

        assert.ok(domain, "ensureDomainValidation(): domain is a required argument");

        const opts = Object.assign({}, {
            min_expires_at: Math.floor(Date.now() / 1000) + 7 * 86400
        }, options);
        // minimum expiration

        await this.deleteUnverifiedDomainValidationClaims(domain);

        const existingClaims = await this.listDomainValidationClaims(domain);
        log_debug('domain %s existing claims: %j', domain, existingClaims);

        existingClaims.forEach(claimInfo => {
            assert.equal(claimInfo.status, 'VERIFIED', "Existing claims expected to be verified after running deleteUnverifiedDomainValidationClaims");
        });

        assert.ok(existingClaims.length <= 1, "Number of domain claims is expected to be zero or one");

        if (existingClaims.length === 0) {
            // No claims - do new one
            const claimId = await this.createDomainValidationClaim(domain);
            await this.assertDomainValidationClaim(claimId);
            const claimInfo = await this.getDomainValidationClaim(claimId);
            assert.ok(
                claimInfo.expires_at >= opts.min_expires_at,
                `New claim expiration is less than specified by min_expires_at. domain=${domain} claim=${JSON.stringify(claimInfo)}`
            );
            return true;
        }

        const claimInfo = existingClaims[0];
        if (claimInfo.expires_at >= opts.min_expires_at) {
            log_debug('Claim expiration is OK. domain=%s. claim=%j. min_expires_at=%s', domain, claimInfo, opts.min_expires_at);
            return false;
        }

        await this.reassertDomainValidationClaim(claimInfo.id);
        const updatedClaimInfo = await this.getDomainValidationClaim(claimInfo.id);
        assert.ok(
            updatedClaimInfo.expires_at >= opts.min_expires_at,
            `Reasserted claim expiration is less than specified by min_expires_at. domain=${domain} claim=${JSON.stringify(updatedClaimInfo)}`
        );

        return true;
    }

    /**
     * @param claimId
     * @param {function} checker - must throw an exception if the check fails
     */
    async _assertDomainValidationClaim(claimId, checker) {

        const gsDNS = require(DNS_MODULE);
        /**
         * @type {DomainValidationClaim}
         */
        const claimBeforeOperation = await this.getDomainValidationClaim(claimId);

        if(gsDNS.preflightCheck) {
            await gsDNS.preflightCheck(claimBeforeOperation.domain);
        }

        log_update(`Asserting domain validation claim ${claimId}`);
        let claim = await this._makeAuthorizedRequest({
            method: "POST",
            uri: apiEndpoint + "/v2/claims/domains/" + claimId + "/reassert",
            json: true
        });
        /**
         * @type ClaimAssertion
         */
        const requiredAssertion = claim.body;
        // debug('CLAIM BODY', claim.body);

        log_update(`Will call DNS with ${claimBeforeOperation.domain} and ${requiredAssertion.token}`);
        await gsDNS.replaceTxtRecord(claimBeforeOperation.domain, `"${requiredAssertion.token}"`);

        await _retry(DNS_ATTEMPTS, DNS_SLEEP, 'waitDnsDv', async () => {
            const dnsReply = await util.promisify(dns.resolve.bind(dns))(claimBeforeOperation.domain, 'TXT');
            assert.ok(dnsReply.some(arr => arr.some(elt => elt === requiredAssertion.token)), `DNS reply must include TXT record ${requiredAssertion.token}`);
            return `DNS record found for ${requiredAssertion.token}`;
        });

        let claimAfterOperation = null;
        await _retry(CLAIM_ATTEMPTS, CLAIM_SLEEP, 'claimDv', async () => {
            await this.submitValidationClaim(claimId);
            await new Promise(accept => setTimeout(accept, 5000));
            /**
             * @type {DomainValidationClaim}
             */
            claimAfterOperation = await this.getDomainValidationClaim(claimId);
            // assert.ok(claimBeforeOperation.expires_at !== claimAfterOperation.expires_at, "New claim expiration must be later");
            await checker(claimBeforeOperation, claimAfterOperation);
        });

        return claimAfterOperation;
    }

    async _makeAuthorizedRequest(options) {
        let response;
        const opts = Object.assign({}, options, {
            simple: false,
            cert: Buffer.from(this._mtlsCredentials.gs_mtls_cert, 'utf8'),
            key: Buffer.from(this._mtlsCredentials.gs_mtls_pk, 'utf8'),
            resolveWithFullResponse: true,
            headers: Object.assign({}, {
                "Content-Type": "application/json; charset=UTF-8"
            }, options.headers)
        });

        if(options.method !== 'GET') {
            log_update(`Calling GlobalSign HVCA API: ${opts.method} ${opts.uri}`);
        }

        // Can not use _retry() here because there are cases in which the error is permanent and
        // we should not continue retrying. _retry() does not support permanent errors,
        // it will continue retrying for the given number of attempts.
        for (let i = 0; i < API_CALL_ATTEMPTS; i++) {
            await this.login();
            opts.headers.Authorization = "Bearer " + this._accessToken;
            response = await rp(opts);
            if (response.statusCode < 400) {
                return response;
            }
            if (response.statusCode === 429) {
                // Transient error. Will retry.
                await new Promise(resolve => setTimeout(resolve, API_CALL_SLEEP));
                continue;
            }
            // Permanent error, not retrying.
            const e = new Error(`Request failed: ${response.request.method} ${response.request.href} - ${response.statusCode} ${JSON.stringify(response.body)}`);
            e.response = response;
            throw e;
        }
        if (response) {
            throw new Error(`Failed to _makeAuthorizedRequest() ${response.request.method} ${response.request.href}. Last response - ${response.statusCode} ${JSON.stringify(response.body)}`);
        } else {
            throw new Error(`Failed to _makeAuthorizedRequest()`);
        }
    }
}

module.exports = {
    GlobalSignHVCAClient
};
