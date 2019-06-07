const dns = require('dns');
const IPCIDR = require('ip-cidr');
const { parse } = require('tldjs');

var spfDNSRecord = [];

const parseARecord = (domain) => {
    dns.resolve4(`${domain}`, 'A', (err, record) => {
        if(err) {
            console.error(err);
            return err.code;
        } else {
            return record[0];
        }
    });
}

const parseAAAARecord = (domain) => {
    dns.resolve6(`${domain}`, 'AAAA', (err, record) => {
        if(err) {
            console.error(err);
            return err.code;
        } else {
            return record;
        }
    });
}

const parseMXRecord = (domain) => {
    dns.resolveMx(`${domain}`, 'MX', (err, record) => {
        if(err) {
            console.error(err);
            return err.code;
        } else {
            return record;
        }
    });
}

const parseCNAMERecord = (domain) => {
    dns.resolveCname(`${domain}`, 'CNAME', (err, record) => {
        if(err) {

        } else {

        }
    });
}

const parsePTRRecord = (domain) => {
    dns.resolveMx(`${domain}`, 'PTR', (err, record) => {
        if(err) {

        } else {
            
        }
    });
}

const parseIPRecord = (ip_address) => {
    let range = new IPCIDR(`${ip_address}`).toRange();
    return { first : range[0], second : range[1]};
}

const validateDomain = (domain) => {
    let parsedDomain = parse(domain);
    console.log(parsedDomain);
    if(parsedDomain.isValid) {
        console.log('Domain is valid');
        
        parseSPFRecord(parsedDomain.domain);
    }
    let pubSuFLen = parsedDomain.publicSuffix.split('.').length;
    console.log(pubSuFLen);
    
}

const parseSPFRecord = (domain) => {
    var spfRecord = [];
    dns.resolveTxt(`${domain}`, (err, records) => {
        if(err) {
            // console.log(`Error : ${err.code}`);
            if(err.code === 'ENODATA') {
                console.error('Domain does not exists');
            }
        } else {
            console.log(`DNS TXT : `);
            let txtRecords = [];
            records.map((record,index) => {
                console.log(`Record  ${index} : ${record}`);
                if(record.length > 1) {
                    let spf = '';
                    record.map((substr, index) => {
                        spf += substr; // to make the different spf strings as one
                    });
                    txtRecords.push(spf.split(' '));
                } else {
                    txtRecords.push(record[0].split(' '));
                }
            });
            // console.log(txtRecords);
            // let spfRecord;
            txtRecords.map((item, index) => {
                item.map((item2, index2) => {
                    if(item2 === 'v=spf1') {
                        console.log('Got it');
                        spfRecord = txtRecords[index];
                        spfRecord.shift();
                        console.log(spfRecord);
                        return;
                    } 
                    // else {
                    //     console.log(`${index2}`)
                    // }
                });
            });
            console.log(txtRecords);
            spfRecord.map((type, index) => {
                if(type === 'a') {
                    spfDNSRecord.push({ type : 'A', address : parseARecord(domain)});
                } else if(type === 'aaaa') {
                    spfDNSRecord.push({ type : 'AAAA', address : parseAAAARecord(domain)});
                } else if(type === 'cname') {
                    spfDNSRecord.push({ type : 'CNAME', domain : parseCNAMERecord(domain)});
                } else if(type === 'mx') {
                    spfDNSRecord.push({type : 'MX', domain : parseMXRecord(domain)});
                } else if(type === 'ptr') {
                    spfDNSRecord.push({type : 'PTR', domain : parsePTRRecord(domain)});
                } else if(type.split(':')[0] === 'include') {
                    parseSPFRecord(type.split(':')[1]);
                    return ;
                } else if(type.split(':')[0] === 'ip4') {
                    spfDNSRecord.push(parseIPRecord(type.split(':')[1]));
                } else if(type.substring(0,3) === 'ip6') {
                    spfDNSRecord.push(parseIPRecord(type.substring(4)));
                } else if (type === '+all' || type === '-all' || type === '~all') {
                    return ;
                }
            });
            console.log(spfDNSRecord);
        }
    });
}

validateDomain('flipkart.com');

module.exports = {
    parseSPFRecord, validateDomain, 
}