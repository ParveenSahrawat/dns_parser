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
    permError : 'permerror', 
}

var spfDNSRecord = [];
var results = [];
var dnsLookUpCount = 0;
var dnsLookUpMechanismsCount = 0;

const _parseIPRecord = (ip_address) => {
    let range = new IPCIDR(`${ip_address}`).toRange();
    return { first : range[0], second : range[1]};
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
        let domainName = parsedDomain.domain.split('.')[parsedDomain.domain.split('.').length - pubSufLen - 1];
        if(domainName.length > 63) {
            console.error("Domain length is greater than 63 characters.");
        }
    }
}

const _parseSPFRecord = (domainName) => {
    // var spfRecord = [];
    const domain = domainName;
    dns.resolveTxt(`${domain}`, (err, records) => {
        if(err) {
            if(err.code === 'SERVFAIL' || err.code === 'TIMEOUT')
                results.push({ serverError :  queryResults.tempError,
                    description : err.Error });
            else 
                results.push({error : err});
        } else {
            dnsLookUpCount++
            console.log(`DNS TXT : `);
            var txtRecords;
            console.log(`Records length is ${records.length}`);

            // get spf record if available and there exists only one spf record
            var spfCount = 0;
            var spf;
            records.map((record,index) => {
                console.log(`Record  ${index} : ${record}`);
                if(record.length > 1) {
                    spfCount++;
                    if(record[0].split(' ')[0] === 'v=spf1') {
                        record.map((substr, index) => {
                            spf += substr; // to make the different spf strings a single string
                        });
                    }
                } else {
                    if(record[0].split(' ')[0] === 'v=spf1') {
                        spfCount++;
                        spf = record[0];
                    }
                }
            });

            if(spfCount === 1) {
                if(spf.length < 513) {
                    txtRecords = [...spf.split(' ')];

                    // spf record last element should be one of below mechanisms or modifiers
                    const mechanismsOrModifiers = ['-all', '+all', '?all', '~all', 'redirect'];
                    // console.log(` Last element is ${txtRecords[txtRecords.length - 1]}`);
                    if(mechanismsOrModifiers.indexOf(txtRecords[txtRecords.length - 1])) {

                    }
                } else {
                    console.error("Spf length is more than 512 octets");
                    results.push({type : 'Invalid spf', description : 'Length of the spf record is more than 512 octets.'});
                }
            } else {
                console.log(`spf count is ${spfCount}`);
            }
            // to check the count of redirect and exp modifiers
            for(let rec = 0; rec < txtRecords.length; rec++) {
                console.log(txtRecords[rec]);
                var mechOrModifr = txtRecords[txtRecords.length - 1];
                if(mechOrModifr === 'redirect') {
                    redirectCount++;
                } else if(mechOrModifr === 'exp') {
                    expCount++;
                }
            }
            // var spfRecord;
            if(spfCount === 1){
                for(let i = 0; i < txtRecords.length; i++){
                    console.log('Got it');
                        let type = txtRecords[i];
                        var redirectCount = 0,
                            expCount = 0;
                            // spfRecord = [...txtRecords];
                            // spfRecord.shift();
                            // console.log(spfRecord);

                        // spfRecord.map((type) => {
                            if(type === 'a' || type.split(':')[0] === 'a' || type.split('/')[0] === 'a') {
                                dnsLookUpCount++
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
                            } else if(type === 'aaaa') {
                                dnsLookUpCount++
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
                            } else if(type === 'mx') {
                                dnsLookUpCount++;
                                let mxRecord = new Promise((resolve, reject) => {
                                    dns.resolveMx(domain, (err, record) => {
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                mxRecord.then(record => {
                                    spfDNSRecord.push({ type : 'MX', domains : [...record] });
                                    record.map((item) => {
                                        let exchangeRecord = new Promise((resolve, reject) => {
                                            console.log(`Item : ${item.exchange}`);
                                            dns.resolveMx(item.exchange, (err, resourceRecord) => {
                                                err ? reject(err) : resolve(resourceRecord);
                                            });
                                        });
                                        exchangeRecord.then(data => {
                                            spfDNSRecord.push({mxResourceRecord : data});
                                        }).catch(err => {
                                            results.push({error : err, description : 'Resource record error'});
                                        });
                                    });
                                }).catch(err => {
                                    results.push({ error : err});
                                });
                            } else if(type === 'ptr') {
                                dnsLookUpCount++;
                                let ptrRecord = new Promise((resolve, reject) => {
                                    dns.resolvePtr(domain, (err, record) => {
                                        err ? reject(err) : resolve(record);
                                    });
                                });
                                ptrRecord.then(record => {
                                    spfDNSRecord.push({ type : 'PTR', record : record});
                                }).catch(err => {
                                    results.push({error : err});
                                });
                            } else if(type.split(':')[0] === 'exists') {
                                console.log('\n Exists Exists \n');
                            } else if(type.split(':')[0] === 'include') {
                                dnsLookUpCount++;
                                _parseSPFRecord(type.split(':')[1]);
                                return ;
                            } else if(type.split(':')[0] === 'ip4') {
                                spfDNSRecord.push(_parseIPRecord(type.split(':')[1]));
                            } else if(type.substring(0,3) === 'ip6') {
                                spfDNSRecord.push(_parseIPRecord(type.substring(4)));
                            } else if (type === '+all' || type === '-all' || type === '~all' || type === '?all') {
                                return ;
                            }
                            // });
                            console.log(spfDNSRecord);
                            console.log(results);
                }
            } else {

            }
        }
        console.log(results);
    });
}

_validateDomain('paavu.com');

module.exports = {
    _parseSPFRecord, _validateDomain, 
}