'use strict'
var Promise = require('bluebird');
const dns = require('dns');
const IPCIDR = require('ip-cidr');
const { parse } = require('tldjs');
const pify = require('pify');

const resultsCodes = {
    spfCount : 1000, // if spf count is greater then 1
    domainInvalid : 1001, // if domain is invalid
    domainLength : 1002, // if domain length is greater than 63 characters
    domainNotFound : 1003, // if domain is not found 
    voidLookUp : 1004, // if void lookup count is exceeded 2
    dnsLookUp : 1005, // if dns lookup count has been exceeded 10
    itemAfterAll : 1006, // if items are present after all mechanism
}
const queryResults = {
    none : 'none',
    neutral : 'neutral',
    pass : 'pass',
    fail : 'fail',
    softFail : 'softfail',
    tempError : 'temperror', // If the DNS lookup returns a server failure or 
                            // some other error or if the lookup times out, then 
                            // check_host() terminates immediately with the result "temperror".
    permError : 'permerror', //
}
var dnsLookUpCount = 0;
var voidLookUpCount = 0;
var results = [];
var domainGlobal = 'flipkart.com';

const _parseIPRecord = (ip_address) => {
    let range = new IPCIDR(`${ip_address}`).toRange();
    return { first : range[0], last : range[1]};
}

const _validateDomain = (domain) => {
    let parsedDomain = parse(domain);
    console.log(parsedDomain);
    if(parsedDomain.isValid) {
        _parseSPFRecord(parsedDomain.domain);
    } else {
        results.push({ domain : domain, errorCode : resultsCodes.domainInvalid, description : 'Domain is invalid', });
    }
    if(parsedDomain.domain !== null){
        let pubSufLen = parsedDomain.publicSuffix.split('.').length;
        // let domainName = parsedDomain.domain.split('.')[parsedDomain.domain.split('.').length - (pubSufLen + 1)];
        if( (domain.length - (pubSufLen + 1)) > 63) {
            results.push({domain : domain, errorCode : resultsCodes.domainLength, description : 'Domain lenght is greater than 63 characters.'});
            console.error("Domain length is greater than 63 characters.");
        }
    }
    console.log(results);
}
// var spfDNSRecord = []; // for record of data to be collected after spf evaluation
const _parseSPFRecord = (domain) => {
    const domainName = domain;
    
    dns.resolveTxt(`${domainName}`, (err, records) => {
        if(err) {
            if(err.code === 'ENOTFOUND') {
                voidLookUpCount++;
            }
            results.push({domain : domainName, errorCode : resultsCodes.domainNotFound, description : 'Domain not found.'});
            console.log(results);
            console.log(`Void lookups are ${voidLookUpCount}`);
        } else {
            if(records.length === 0) {
                voidLookUpCount++;
            }
            if(voidLookUpCount > 2) {
                results.push({ domain : domainName, voidLookUps : voidLookUpCount, warningCode : resultsCodes.voidLookUp, warning : 'Number of void lookups has been exceeded 2.' });
            }
            var txtRecords;
            console.log(`Records length is ${records.length}`);
            // get spf record if available and there exists only one spf record
            var spfCount = 0;
            var spf;

            records.map((record,index) => {
                console.log(`Record  ${index} : ${record}`);
                let spfVersion = record[0].split(' ')[0];
                if(spfVersion === 'v=spf1') {
                    spfCount++;
                    if(record.length > 1) {
                        record.map((substr) => {
                            spf += substr; // to make the different spf strings a single string
                        });
                    } else {
                        spf = record[0];// when spf exists as a single string
                    }
                }
            });

            if(spfCount === 1) {
                if(spf.length > 512 ) {
                    results.push({ domain : domainName, warning : 'The length of the spf record is exceeded 512 characters'});
                }
                txtRecords = [...spf.split(' ')];
                txtRecords.shift();// to remove v=spf1
                // spf record last element should be one of below mechanisms or modifiers
                const mechanismsOrModifiers = ['-all', '+all', '?all', '~all', 'redirect'];
                // console.log(` Last element is ${txtRecords[txtRecords.length - 1]}`);
                let lastElement = txtRecords[txtRecords.length - 1];
                if( (mechanismsOrModifiers.indexOf(lastElement) > -1) || (mechanismsOrModifiers.indexOf(lastElement.split('=')[0]) > -1) ) {
                    // to check the count of redirect and exp modifiers
                    var redirectCount = 0,
                        expCount = 0;
                    for(let rec = 0; rec < txtRecords.length; rec++) {
                        console.log(txtRecords[rec]);
                        let mechOrModifr = txtRecords[txtRecords.length - 1];
                        if(mechOrModifr === 'redirect') {
                            redirectCount++;
                        } else if(mechOrModifr === 'exp') {
                            expCount++;
                        }
                    } 
                    // count should be 0 or 1 for both exp and redirect in spf record   
                    if( (0 <= redirectCount  <= 2) && ( 0 <= expCount <= 2)) {
                        // evaluate spf records
                        let aOptions = ['a', '-a', '+a', '~a', '?a'];
                        let aaaaOptions = ['aaaa', '-aaaa', '+aaaa', '~aaaa', '?aaaa'];
                        let mxOptions = ['mx', '-mx', '+mx', '~mx', '?mx'];
                        let ptrOptions = ['ptr', '-ptr', '+ptr', '~ptr', '?ptr'];
                        let ip4Options = ['ip4', '-ip4', '+ip4', '~ip4', '?ip4'];
                        let ip6Options = ['ip6', '-ip6', '+ip6', '~ip6', '?ip6'];
                        let allOptions = ['all', '-all', '+all', '~all', '?all'];
                        let existsOptions = ['exists', '-exists', '+exists', '~exists', '?exists'];
                        let includeOptions = ['include', '-include', '+include', '~include', '?include']

                        var spfDNSRecord = []; // for record of data to be collected after spf evaluation

                        for( let i = 0; i < txtRecords.length; i++ ) {
                            if(dnsLookUpCount > 10) { // when dns lookups exceeded 10
                                results.push({permError : queryResults.permError, errorCode : resultsCodes.dnsLookUp, description : 'DNS lookups has been exceeded 10'});
                                console.log(spfDNSRecord);
                                console.log(results);
                                break;
                            }
                            
                            let type = txtRecords[i];
                            if( (aOptions.indexOf(type) > -1) || (aOptions.indexOf(type.split(':')[0]) > -1) || (aOptions.indexOf(type.split('/')[0]) > -1) ) {
                                let aRecord = new Promise((resolve, reject) => {
                                    dns.resolve4(domain, (err, record) => {
                                        dnsLookUpCount++;
                                        console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                aRecord.then((record) => {
                                    if(record.length === 0) {
                                        voidLookUpCount++;
                                    } 
                                    spfDNSRecord.push({ type : 'A', addresses : [...record] });
                                }).catch((err) => {
                                    results.push({error : err});
                                });
                            } else if( (aaaaOptions.indexOf(type) > -1) || (aaaaOptions.indexOf(type.split(':')[0]) > -1) || (aOptions.indexOf(type.split('/')[0]) > -1) ) { 
                                let aaaaRecord = new Promise((resolve, reject) => {
                                    dns.resolve6(doamin, (err, record) => {
                                        dnsLookUpCount++;
                                        console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                aaaaRecord.then(record => {
                                    if(aaaaRecord.length === 0) {
                                        voidLookUpCount++;
                                    }
                                    spfDNSRecord.push({ type : 'AAAA', addresses : [...record] });
                                }).catch(err => {
                                    results.push({error : err});
                                });
                            } else if( (mxOptions.indexOf(type) > -1) || (mxOptions.indexOf(type.split(':')[0]) > -1) || (mxOptions.indexOf(type.split('/')[0]) > -1) ) {
                                
                                console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                let mxRecord = new Promise((resolve, reject) => {
                                    dns.resolveMx(domain, (err, record) => {
                                        dnsLookUpCount++;
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                mxRecord.then(record => {
                                    if(mxRecord === 0) {
                                        voidLookUpCount++;
                                    }
                                    spfDNSRecord.push({ type : 'MX', domains : [...record] });
                                    record.map((item) => {
                                        let mailServerIpv4 = new Promise((resolve, reject) => {
                                            console.log(`Item : ${item.exchange}`);
                                            dns.resolve4(item.exchange, (err, resourceRecord) => {
                                                err ? reject(err) : resolve(resourceRecord);
                                            });
                                        });
                                        let mailServerIpv6 = new Promise((resolve, reject) => {
                                            console.log(`Item : ${item.exchange}`);
                                            dns.resolve6(item.exchange, (err, resourceRecord) => {
                                                err ? reject(err) : resolve(resourceRecord);
                                            });
                                        });
                                        mailServerIpv4.then(data => {
                                            spfDNSRecord.push({mailServer : item.exchange , ip : [...data]});
                                        }).catch(err => {
                                            results.push({error : err, description : 'Error in resolving mail server address.'});
                                        });
                                        mailServerIpv6.then(data => {
                                            spfDNSRecord.push({mailServer : item.exchange , ip : [...data]});
                                        }).catch(err => {
                                            results.push({error : err, description : 'Error in resolving mail server address.'});
                                        });
                                    });
                                }).catch(err => {
                                    results.push({ error : err});
                                });
                            } else if( (ptrOptions.indexOf(type) > -1) || (ptrOptions.indexOf(type.split(':')[0]) > -1) || (ptrOptions.indexOf(type.split('/')[0]) > -1) ) {
                                
                                results.push({ domain : domainName, warning : 'PTR mechanism is found.'});
                                let ptrRecord = new Promise((resolve, reject) => {
                                    dns.resolvePtr(domain, (err, record) => {
                                        dnsLookUpCount++;
                                        console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                ptrRecord.then(record => {
                                    if(record.length === 0) {
                                        voidLookUpCount++;
                                    }
                                    spfDNSRecord.push({ type : 'PTR', record : [...record] });
                                }).catch(err => {
                                    results.push({err});
                                });
                            } else if( (existsOptions.indexOf(type.split(':')[0]) > -1) || (existsOptions.indexOf(type.split('/')[0]) > -1) ) {
                                // a dns lookup will increase here
                                // a void lookup can increase here
                                console.log('\n Exists Exists \n');
                                let domain = type.split(':')[1] || type.split('/')[1];
                                let aRecord = new Promise((resolve, reject) => {
                                    dns.resolve4(domain, (err, record) => {
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                aRecord.then((record) => {
                                    if(record.length === 0) {
                                        voidLookUpCount++;
                                    } 
                                    spfDNSRecord.push({ type : 'exists', address : [...record] });
                                }).catch((err) => {
                                    results.push({error : err});
                                });
                            } else if( (includeOptions.indexOf(type.split(':')[0]) > -1) || (includeOptions.indexOf(type.split('/')[0]) > -1) ) {
                                dnsLookUpCount++;
                                console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                // spfDNSRecord.push(_parseSPFRecord(type.split(':')[1] || type.split('/')[1]));
                                pify(_parseSPFRecord)(type.split(':')[1] || type.split('/')[1]).then((data) => {
                                    spfDNSRecord.push({type : 'include', domain: type.split(':')[1] || type.split('/')[1], data : [...data]});
                                });
                            } else if( (ip4Options.indexOf(type.split(':')[0]) > -1 ) || (ip4Options.indexOf(type.split('/')[0]) > -1 ) ){
                                if(type.split('/')[1] || type.split('/')[2]) {
                                    spfDNSRecord.push(_parseIPRecord(type.split(':')[1]) || _parseIPRecord(type.split('/')[1]));
                                } else {
                                    // If ip4-cidr-length is omitted, it is taken to be "/32".
                                    spfDNSRecord.push(_parseIPRecord(type.split(':')[1] + '/32') || _parseIPRecord(type.split('/')[1] + '/32'));
                                }
                            } else if( (ip6Options.indexOf(type.split(':')[0]) > -1 ) || (ip6Options.indexOf(type.split('/')[0]) > -1 ) ) {
                                if(type.split('/')[1] || type.split('/')[2]) {
                                    spfDNSRecord.push(_parseIPRecord(type.substring(type.split(':')[0].length + 1)) || _parseIPRecord(type.substring(type.split(':')[0].length + 1)));
                                } else {
                                    // If ip6-cidr-length is omitted, it is taken to be "/128".
                                    spfDNSRecord.push(_parseIPRecord(type.substring(type.split(':')[0].length + 1) + '/128') || _parseIPRecord(type.substring(type.split(':')[0].length + 1) + '/128'));
                                }
                            } else if(type.split('=') === 'redirect') {

                                console.log('Redirect is present');
                                
                            } else if (allOptions.indexOf(type) > -1 ) {
                                if( i !== (txtRecords.length -1) ) {
                                    results.push({error : queryResults.tempError, errorCode : resultsCodes.itemAfterAll, description : 'Items present after all mechanism.'})
                                }
                                console.log(spfDNSRecord);
                                results.length > 1 ? console.log(results) : console.log(`No errors`);
                                console.log(`DNS lookups done are ${dnsLookUpCount}.`);
                                console.log(`Void lookups are ${voidLookUpCount}`);
                                if(domainName === domainGlobal) {
                                    break;
                                } else {
                                    return spfDNSRecord;
                                }
                            }
                        }
                    } else {
                        results.push({ permError : queryResults.permError, description : 'redirect or exp has occurred more than once.'});
                    }
                } else {
                    console.log('Neutral');
                    results.push({error : queryResults.neutral, description : 'SPF record is not terminated either by all or redirect.'});
                    console.log(results);
                }
            } else {
                console.log(`spf count is ${spfCount}`);
                results.push({ domain : domainName, errorCode : resultsCodes.spfCount, warning : 'SPF count is more than 1.' });
            }
        }
    });
}

_validateDomain(`${domainGlobal}`);

// dns.resolveMx('paavu.com', (err, result) => {
//     err ? console.error(err) : console.log(result);
// });
// // [
// //     { exchange: 'alt2.aspmx.l.google.com', priority: 5 },
// //     { exchange: 'alt4.aspmx.l.google.com', priority: 10 },
// //     { exchange: 'aspmx.l.google.com', priority: 1 },
// //     { exchange: 'alt1.aspmx.l.google.com', priority: 5 },
// //     { exchange: 'alt3.aspmx.l.google.com', priority: 10 }
// //   ]
// dns.resolve6(`${%{i}._spf.mta.salesforce.com}`, (err, result) => {
//     err ? console.error(err) : console.log(result);
// });