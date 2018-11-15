const assert = require('assert');
const util = require('util');

const NodeRSA = require("node-rsa");
const pem = require("pem");
const x509 = require("x509");

const gs_client = require("../src/gs-client");

if(!process.env.TEST_PLAN_FACTORY) {
    console.error("Environment variable TEST_PLAN_FACTORY must be set");
    process.exit(1);
}

/**
 *
 * @typedef {Object} account
 * @property {String} name
 * @property {Object} subject_dn
 * @property {String[]} dns_names
 * @property {String[]} claims_domains
 */

const testPlanFactory = require(process.env.TEST_PLAN_FACTORY);

if(!process.env.GS_ACCESS_TOKEN_TTL) {
    // Make sure the token expires during the tests
    process.env.GS_ACCESS_TOKEN_TTL = '20';
}

/**
 * @param {String} cert
 * @param {String[]} chain
 * @throws Error
 */
function checkChain(cert, chain) {
    assert.ok(chain && chain.length >= 1, "Trust chain must be present");
    prev = cert;
    for(c of chain) {
        assert.deepEqual(x509.getIssuer(prev), x509.getSubject(c));
        prev = c;
    }
}

testPlanFactory.getTestPlan().then(testPlan => {

    /**
     * @type account[]
     */
    const accounts = testPlan.accounts;

    describe('gs hvca', function () {


        accounts.forEach(account => {

            /**
             * @param {X509CertificatePEM} cert
             * @returns {Promise<void>}
             */
            async function checkCertificate(cert) {
                // TODO: Add CN check
                assert.ok(await (util.promisify(pem.checkCertificate))(cert));
            }


            if(!account.claims_domains) {
                account.claims_domains = [];
            }


            describe('Account "' + account.name + '" - claims', function () {

                this.timeout(10*60*1000); // 10 minutes

                account.claims_domains.forEach(domain => {
                    /**
                     * @type GlobalSignHVCAClient
                     */
                    let gsClient;
                    let claims;
                    let newClaimId;

                    beforeEach(() => {
                        if(!gsClient) {
                            gsClient = new gs_client.GlobalSignHVCAClient(testPlan.mtlsCredentials, account.creds);
                        }
                    });


                    describe('Account "' + account.name + '" - claims for domain ' + domain, function () {

                        step('List claims', async () => {
                            claims = await gsClient.listDomainValidationClaims(domain);
                            // claims.forEach(console.log);
                        });

                        step('Delete claims', async () => {
                            await Promise.all(claims.map(async claim => gsClient.deleteDomainValidationClaim(claim.id)));
                        });

                        step('Domain validation detection when domain is not validated', async () => {
                            assert.equal(await gsClient.isDomainValidated(domain), false);
                        });

                        step('Create claim', async () => {
                            newClaimId = await gsClient.createDomainValidationClaim(domain);
                        });

                        step('Assert claim', async () => {
                            await gsClient.assertDomainValidationClaim(newClaimId);
                            claims = await gsClient.listDomainValidationClaims(domain);
                            assert(claims.length === 1);
                            assert.equal(claims[0].status, 'VERIFIED', "Claim status must be 'VERIFIED'");
                        });

                        step('Domain validation detection when domain is validated', async () => {
                            assert.equal(await gsClient.isDomainValidated(domain), true);
                        });

                        step('Reassert claim', async () => {
                            await gsClient.reassertDomainValidationClaim(newClaimId);
                            const newClaims = await gsClient.listDomainValidationClaims(domain);
                            assert(newClaims.length === 1);
                            assert.equal(newClaims[0].status, 'VERIFIED', "Claim status must be 'VERIFIED'");
                            assert.notEqual(claims[0].expires_at !== newClaims[0].expires_at, "Claims expiration must be different");
                            claims = newClaims;
                        });

                        step('Delete unverified claims when all claims are verified', async () => {
                            await gsClient.deleteUnverifiedDomainValidationClaims(domain);
                            await gsClient.listDomainValidationClaims(domain);
                            assert(claims.length === 1);
                        });

                        step('Delete claim', async () => {
                            await gsClient.deleteDomainValidationClaim(newClaimId);
                            claims = await gsClient.listDomainValidationClaims(domain);
                            assert(claims.length === 0);
                        });

                        step('Create claim not to be submitted', async () => {
                            newClaimId = await gsClient.createDomainValidationClaim(domain);
                            claims = await gsClient.listDomainValidationClaims(domain);
                            assert(claims.length === 1);
                        });

                        step('Delete unverified claims when there is unverified claim', async () => {
                            await gsClient.deleteUnverifiedDomainValidationClaims(domain);
                            claims = await gsClient.listDomainValidationClaims(domain);
                            assert(claims.length === 0);
                        });

                        // Important to leave the domain in working state
                        step('Ensure domain validation', async () => {
                            await gsClient.ensureDomainValidation(domain);
                            claims = await gsClient.listDomainValidationClaims(domain);
                            assert(claims.length === 1);
                            const min_expires_at = claims[0].expires_at + 1;
                            await gsClient.ensureDomainValidation(domain, {min_expires_at});
                            claims = await gsClient.listDomainValidationClaims(domain);
                            assert(claims.length === 1);
                            assert(claims[0].expires_at >= min_expires_at);
                        });
                    });
                });
            });


            describe('Account "' + account.name + '" - certificates', function () {
                this.timeout(60000);

                let gsClient;
                let validationPolicy;
                let certificateUrl;
                let certificates = [];
                let trustChain;

                function makeCreateCertificateArguments() {
                    const key = new NodeRSA();
                    key.setOptions({signingScheme: "pkcs1-sha256"});
                    key.generateKeyPair();
                    let publicKeyPem = key.exportKey("pkcs8-public-pem");
                    let publicKeyDer = key.exportKey('pkcs8-public-der');
                    let signature;

                    if (validationPolicy.public_key_signature !== 'FORBIDDEN') {
                        signature = key.sign(publicKeyDer).toString("base64");
                    } else {
                        signature = null;
                    }

                    return [publicKeyPem, signature, account.subject_dn, 3600, (account.dns_names || null)];
                }

                beforeEach(() => {
                    if(!gsClient) {
                        gsClient = new gs_client.GlobalSignHVCAClient(testPlan.mtlsCredentials, account.creds);
                    }
                });

                step('Get validation policy', async function () {
                    validationPolicy = await gsClient.getValidationPolicy();
                    // console.log(account.name, validationPolicy);
                });

                step('Get trust chain', async function() {
                    trustChain = await gsClient.getTrustChain();
                    assert.ok(trustChain.length > 0, "Trust chain length must be greater than zero");
                    // console.log(trustChain);
                });

                step('Request certificate', async function () {

                    try {
                        certificateUrl = await gsClient.createCertificate(...makeCreateCertificateArguments());
                    } catch (e) {
                        console.log(`Failed to get certificate ${e}. Validation policy is `, JSON.stringify(validationPolicy));
                        throw e;
                    }

                });

                step('Fetch requested certificate', async function () {
                    /**
                     * @type {X509CertificatePEM}
                     */
                    certificates.push(await gsClient.retrieveCertificate(certificateUrl));
                    // console.log(certificate);
                });

                step('Check received certificate - result of createCertificate() and retrieveCertificate()', async function () {
                    assert.ok(certificates && certificates.length >= 1, "There must be certificates to checkCertificate()");
                    await checkCertificate(certificates[0]);
                    checkChain(certificates[0], trustChain);
                });

                step('Create and fetch certificate in one go', async function () {
                    certificates.push(await gsClient.createAndRetrieveCertificate(...makeCreateCertificateArguments()));
                });

                step('Check received certificate - result of createAndRetrieveCertificate()', async function () {
                    assert.ok(certificates.length >= 2, "There must be certificates to checkCertificate()");
                    await checkCertificate(certificates[1]);
                    checkChain(certificates[1], trustChain);
                });

                step('Check certificates are different', function () {
                    assert.ok(certificates[0] !== certificates[1]);
                });

            });
        });
    });
    run();
});

