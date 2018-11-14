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

	await gsClient.assertDomainValidationClaim(newClaimId);
	
