"use strict";
const AWS = require('aws-sdk');
const util = require("util");

const secretManagerClient = new AWS.SecretsManager({
    region: 'us-west-2'
});

const accounts = [
    {
        name: 'Our endpoints',
        _secretName: 'XXX',
        subject_dn: {
            common_name: "test.our-api-domain.example.com"
        }
    },
    {
        name: 'Our devices',
        _secretName: 'XXX',
        subject_dn: {
            organizational_unit: ["TestOU"]
        },
        dns_names: ["test.our-devices-domain.example.com"],
        claims_domains: ["our-devices-domain.example.com"]
    },
    {
        name: 'Main account',
        _secretName: 'XXX',
        subject_dn: {
            common_name: 'test.our-main-domain.example.com',
            country: 'IL',
            locality: 'Tel Aviv-Jaffa',
            organization: 'Our-org Ltd',
            state: 'Tel Aviv',
        },
        dns_names: ["test.our-main-domain.example.com"],
    }
];

async function getTestPlan() {
    await Promise.all(accounts.map(account => retrieveSecret(account._secretName).then(x => account.creds = x)));
    return {
        accounts,
        mtlsCredentials: await getMtlsCredentials()
    };
}

async function getMtlsCredentials() {
    return await retrieveSecret('XXX-GLOBAL-MTLS-CREDS');
}

async function retrieveSecret(secretName) {
    let secret;
    const data = await (util.promisify(secretManagerClient.getSecretValue.bind(secretManagerClient)))({SecretId: secretName});

    if (data.SecretString !== "") {
        secret = data.SecretString;
    } else {
        throw new Error("Binary secrets are not implemented");
    }

    secret = JSON.parse(secret);
    return secret;
}

module.exports = {
    getTestPlan
};
