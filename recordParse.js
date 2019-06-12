'use strict'

const dns = require('dns');
const IPCIDR = require('ip-cidr');
const { parse } = require('tldjs');
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

var results = [];

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
        results.push({error : 'Domain is invalid'});
    }
    if(parsedDomain.domain !== null){
        let pubSufLen = parsedDomain.publicSuffix.split('.').length;
        let domainName = parsedDomain.domain.split('.')[parsedDomain.domain.split('.').length - (pubSufLen + 1)];
        if(domainName.length > 63) {
            console.error("Domain length is greater than 63 characters.");
        }
    }
}

const _parseSPFRecord = (domain) => {
    const domainName = domain;
    
    dns.resolveTxt(`${domainName}`, (err, records) => {
        if(err) {
            console.error(err);
        } else {
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
                if(spf.length > 513 ) {
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

                        let spfDNSRecord = []; // record of data to be collected after spf evaluation

                        for( let i = 0; i < txtRecords.length; i++ ) {
                            // if(dnsLookUpCount > 10) { // when dns lookups exceeded 10
                            //     results.push({permError : queryResults.permError, description : 'DNS lookups has been exceeded 10'});
                            //     console.log(spfDNSRecord);
                            //     console.log(results);
                            //     break;
                            // }
                            
                            let type = txtRecords[i];
                            if( (aOptions.indexOf(type) > -1) || (aOptions.indexOf(type.split(':')[0]) > -1) || (aOptions.indexOf(type.split('/')[0]) > -1) ) {
                                dnsLookUpCount++;
                                console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                let aRecord = new Promise((resolve, reject) => {
                                    dns.resolve4(domain, (err, record) => {
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                aRecord.then((record) => {
                                    spfDNSRecord.push({ type : 'A', address : record[0] });
                                }).catch((err) => {
                                    results.push({error : err});
                                });
                            } else if( (aaaaOptions.indexOf(type) > -1) || (aaaaOptions.indexOf(type.split(':')[0]) > -1) || (aOptions.indexOf(type.split('/')[0]) > -1) ) { 
                                dnsLookUpCount++;
                                console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                let aaaaRecord = new Promise((resolve, reject) => {
                                    dns.resolve6(doamin, (err, record) => {
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                aaaaRecord.then(record => {
                                    spfDNSRecord.push({ type : 'AAAA', address : record[0] });
                                }).catch(err => {
                                    results.push({error : err});
                                });
                            } else if( (mxOptions.indexOf(type) > -1) || (mxOptions.indexOf(type.split(':')[0]) > -1) || (mxOptions.indexOf(type.split('/')[0]) > -1) ) {
                                dnsLookUpCount++;
                                console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                let mxRecord = new Promise((resolve, reject) => {
                                    dns.resolveMx(domain, (err, record) => {
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                mxRecord.then(record => {
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
                                            spfDNSRecord.push({mailServer : item.exchange , ip : data.exchange});
                                        }).catch(err => {
                                            results.push({error : err, description : 'Error in resolving mail server address.'});
                                        });
                                        mailServerIpv6.then(data => {
                                            spfDNSRecord.push({mailServer : item.exchange , ip : data.exchange});
                                        }).catch(err => {
                                            results.push({error : err, description : 'Error in resolving mail server address.'});
                                        });
                                    });
                                }).catch(err => {
                                    results.push({ error : err});
                                });
                            } else if( (ptrOptions.indexOf(type) > -1) || (ptrOptions.indexOf(type.split(':')[0]) > -1) || (ptrOptions.indexOf(type.split('/')[0]) > -1) ) {
                                dnsLookUpCount++;
                                console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                results.push({ domain : domainName, warning : 'PTR records are found.'});
                                let ptrRecord = new Promise((resolve, reject) => {
                                    dns.resolvePtr(domain, (err, record) => {
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                ptrRecord.then(record => {
                                    spfDNSRecord.push({ type : 'PTR', record : record });
                                }).catch(err => {
                                    results.push({error : err});
                                });
                            } else if( (existsOptions.indexOf(type.split(':')[0]) > -1) || (existsOptions.indexOf(type.split('/')[0]) > -1) ) {
                                // a dns lookup will increase here
                                console.log('\n Exists Exists \n');
                            } else if( (includeOptions.indexOf(type.split(':')[0]) > -1) || (includeOptions.indexOf(type.split('/')[0]) > -1) ) {
                                dnsLookUpCount++;
                                console.log(`DNS lookups done are ${dnsLookUpCount}`);
                                    _parseSPFRecord(type.split(':')[1] || type.split('/')[1]);
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
                                    results.push({error : queryResults.tempError, description : 'Items present after all mechanism.'})
                                }
                                console.log(spfDNSRecord);
                                results.length > 1 ? console.log(results) : console.log(`No errors`);
                                console.log(`DNS lookups done are ${dnsLookUpCount}.`);
                                break;
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
                results.push({ domain : domainName, warning : 'SPF count is more than 1.' });
            }
        }
    });
}

_validateDomain('paavu.com');
