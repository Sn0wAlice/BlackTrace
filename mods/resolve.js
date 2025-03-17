const dns = require('dns');


function resolveARecords(domain) {
    return new Promise(resolve => {
        dns.resolve(domain, 'A', (err, addresses) => {
            if (err) {
                console.error(`{-} Error resolving ${domain}: no records found`);
                resolve([]);
            } else {
                console.log(`{+} A records for ${domain}:`, addresses);
                resolve(addresses);
            }
        });
    })
}

async function resolveTXTRecords(domain) {
    return new Promise(resolve => {
        dns.resolveTxt(domain, (err, records) => {
            if (err) {
                console.error(`{-} Error resolving SPF for ${domain}: no records found`);
                resolve([]);
            } else {
                console.log(`{+} TXT records for ${domain}:`, records.length);
                let tmp = records.map((r) => r.join(''));
                resolve(tmp);
            }
        });
    })
}


exports.resolver =  async function (domains) {
    let resolved_domains = [];

    for (const d of domains) {
        let tmp = await resolveARecords(d);
        resolved_domains.push({
            domain: d,
            ips: tmp
        });
    }

    return resolved_domains;
}

async function spf_check(domain) {
    let tmp = await resolveTXTRecords(domain);
    return tmp.filter((r) => r.includes('v=spf'));
}

async function dmarc_check(domain) {
    let tmp = await resolveTXTRecords(domain);
    return tmp.filter((r) => r.includes('v=DMARC'));
}

exports.mailsecurity =  async function (domain) {
    let spf = await spf_check(domain);
    let dmarc = await dmarc_check(`_dmarc.${domain}`);

    return {
        spf: {
            enable: spf.length > 0,
            records: spf
        },
        dmac: {
            enable: dmarc.length > 0,
            records: dmarc
        }
    }
}
