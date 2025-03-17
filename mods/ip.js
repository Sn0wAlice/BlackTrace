const fs = require('fs');

function ipToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function intToIp(int) {
    return [
        (int >>> 24) & 0xFF,
        (int >>> 16) & 0xFF,
        (int >>> 8) & 0xFF,
        int & 0xFF
    ].join('.');
}

function cidrToIpList(cidr) {
    const [range, prefixLength] = cidr.split('/');
    const startIpInt = ipToInt(range);
    const maskLength = parseInt(prefixLength, 10);
    const numberOfHosts = Math.pow(2, 32 - maskLength);

    const ipList = [];
    for (let i = 0; i < numberOfHosts; i++) {
        ipList.push(intToIp(startIpInt + i));
    }

    return ipList;
}

function convert_range_to_ip_list(blacklistRanges) {
    let allIps = [];
    for (const cidr of blacklistRanges) {
        allIps = allIps.concat(cidrToIpList(cidr));
    }
    return allIps;
}


const cloudflare = convert_range_to_ip_list(JSON.parse(fs.readFileSync('./ips/cloudflare.json', 'utf8')));


function categorize(ip) {
    let category = 'unknown';

    if (cloudflare.includes(ip)) {
        category = 'cloudflare';
    }

    return {
        ip: ip,
        category: category
    }
}



exports.categorize = async function (ips) {
    let all = [];

    for (const ip of ips) {
        all.push(categorize(ip));
    }

    return all;
}