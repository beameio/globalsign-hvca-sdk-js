# GlobalSign HVCA client

This readme is WIP.

## Create API client

	gsClient = new gs_client.GlobalSignHVCAClient(mtlsCreds, accountCreds);

## Domain validation

### Ensure domain is validated

The following command will do everything needed to create or update domain validation claim.

	await gsClient.ensureDomainValidation(domain);

*Rest of the domain validation commands below are low level and should not be used
unless you are sure about what you are doing.*

### List domain validation claims

	claims = await gsClient.listDomainValidationClaims(domain);
	
### Delete all domain validation claims

	await Promise.all(claims.map(async claim => gsClient.deleteDomainValidationClaim(claim.id)));

### Check whether domain is validated

	await gsClient.isDomainValidated(domain);

### Create new domain validation claim

	newClaimId = await gsClient.createDomainValidationClaim(domain);
	
### Assert domain validation claim

	await gsClient.assertDomainValidationClaim(claimId);
	
### Reassert domain validation claim

	await gsClient.reassertDomainValidationClaim(claimId);

### Delete all unverified domain validation claims

	await gsClient.deleteUnverifiedDomainValidationClaims(domain);

## Certificates

### Create and fetch certificate

The following code is extracted from tests and should work with minor modifications
such as substituting variables in order to pass the correct data into the function calls.

	gsClient = new gs_client.GlobalSignHVCAClient(mtlsCreds, accountCreds);

	const NodeRSA = require("node-rsa");
    const key = new NodeRSA();
    key.setOptions({signingScheme: "pkcs1-sha256"});
    key.generateKeyPair();
    let publicKeyPem = key.exportKey("pkcs8-public-pem");
    let publicKeyDer = key.exportKey('pkcs8-public-der');
    let signature;

    validationPolicy = await gsClient.getValidationPolicy();

    if (validationPolicy.public_key_signature !== 'FORBIDDEN') {
        signature = key.sign(publicKeyDer).toString("base64");
    } else {
        signature = null;
    }

    await gsClient.createAndRetrieveCertificate(publicKeyPem, signature, subject_dn, 3600, dns_names || null)

    // Same as: await createCertificate() and then retrieveCertificate()

### Get trust chain

	trustChain = await gsClient.getTrustChain();
