'use strict';

const util = require('util');
const assert = require('assert');

const AWS         = require('aws-sdk');
const route53     = new AWS.Route53();

const log_update = require('debug')('gs-client:update');

const TTL = Number.parseInt(process.env.GS_DNS_TTL) || 60;

// TODO: short-live caching so that preflightCheck and following replaceTxtRecord would only generate on API call
async function _getZone(domain) {
    const params = {
        DNSName: domain,
        MaxItems: '2'
    };
    const zones = (await route53.listHostedZonesByName(params).promise())
        .HostedZones
        .filter(z => z.Name === domain);
    assert.equal(zones.length, 1, `Don't know how to handle multiple (or none) DNS zones for domain ${domain}. Expected exactly one zone.`);
    return zones[0];
}

async function preflightCheck(domain) {
    await _getZone(domain);
}

async function _getRRSets(zone) {
    const params = {
        HostedZoneId: zone.Id,
        StartRecordName: zone.Name,
        StartRecordType: 'TXT',
        MaxItems: '1',
    };

    // console.log(zone);

    const rrsets = (await route53.listResourceRecordSets(params).promise())
        .ResourceRecordSets
        .filter(x => x.Name === params.StartRecordName || x.Type === params.StartRecordType);

    assert.ok(rrsets.length <= 1, `Expected exactly one ResourceRecordSets for ${params.StartRecordName} and ${params.StartRecordType}`);

    return rrsets;
}

async function replaceTxtRecord(domain, value) {

    const valueParts = value.split('=');
    const zone = await _getZone(domain);
    const rrsets = await _getRRSets(zone);

    // console.log(rrsets);

    let existingResourceRecords = [];
    if (rrsets.length === 1) {
        existingResourceRecords = rrsets[0].ResourceRecords;
    }

    const params = {
        ChangeBatch:  {
            Changes: [
                {
                    Action:            'UPSERT',
                    ResourceRecordSet: {
                        Name:            domain,
                        Type:            'TXT',
                        ResourceRecords: existingResourceRecords.filter(x => !x.Value.startsWith(valueParts[0] + '=')).concat([
                            {
                                Value: value
                            },
                        ]),
                        TTL:             TTL
                    }
                },
            ],
            Comment: `By GlobalSign DNS on ${new Date().toISOString()} for domain validation.`
        },
        HostedZoneId: zone.Id
    };


    log_update('Calling route53.changeResourceRecordSets', JSON.stringify(params));

    await route53.changeResourceRecordSets(params).promise();
    // (params, function(err, data) {
    //     if (err) console.log(err, err.stack); // an error occurred
    //     else     console.log(data);           // successful response
    // });
}

module.exports = {
    preflightCheck,
    replaceTxtRecord
};
