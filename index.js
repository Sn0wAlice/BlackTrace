const fs = require('fs');

// custom mods
const subfinder = require('./mods/subfinder.js');
const resolver = require('./mods/resolve.js');
const ip = require('./mods/ip.js');
const nmap = require('./mods/nmap.js');


async function scan_domain(domain) {
    let markdown_report = `# Recon Report for ${domain}\n\n`;

    // Step 1: Get subdomains
    console.log(`+-------------------------------------+`);
    console.log(`{+} Getting subdomains for ${domain}\n`);
    let domain_list = await subfinder.subfinder(domain);
    console.log(`{+} Found ${domain_list.length} subdomains`);
    markdown_report += `## Subdomains\n`;
    domain_list.forEach(subdomain => {
        markdown_report += `- ${subdomain}\n`;
    });

    markdown_report+=`\n\n`;

    // Step 2: Resolve the subdomains
    console.log(`\n+-------------------------------------+`);
    console.log(`{+} Resolving ${domain_list.length} domain\n`);
    let resolved_domains = await resolver.resolver(domain_list);

    // Markdown table for the resolved domains
    markdown_report += `## Resolved Domains\n`;
    markdown_report += `| Domain | IPs | \n| --- | --- |\n`;
    resolved_domains.forEach(domain => {
        markdown_report += `| ${domain.domain} | ${domain.ips.join(', ')} |\n`;
    })

    let iplist = [];
    for (let d of resolved_domains) {
        iplist = iplist.concat(d.ips);
    }

    // remove duplicates
    iplist = [...new Set(iplist)];
    let categorized = await ip.categorize(iplist);

    markdown_report += `\n\n`;
    markdown_report += `## Categorized IPs\n`;
    markdown_report += `| IP | Category | \n| --- | --- |\n`;
    categorized.forEach(category => {
        markdown_report += `| ${category.ip} | ${category.category} |\n`;
    });
    

    // Step 3: scan open ports
    console.log(`\n+-------------------------------------+`);
    console.log(`{+} Scan open ports for ${categorized.length} IPs\n`);
    let open_ports = await nmap.nmap(categorized);

    markdown_report += `\n\n`;
    markdown_report += `## Open Ports\n`;
    for (let ip of open_ports) {
        markdown_report += `### ${ip.ip}\n`;
        markdown_report += `| Port | Service | http server ? | \n| --- | --- | --- |\n`;
        ip.ports.forEach(port => {
            markdown_report += `| ${port.port} | ${port.service} | ${port.is_web_server ? "true" : "false"} |\n`;
        });
    }


    // Step 4: mail security
    console.log(`\n+-------------------------------------+`);
    console.log(`{+} Checking mail security for ${domain}\n`);
    let mail_security = await resolver.mailsecurity(domain);

    markdown_report += `\n\n`;
    markdown_report += `## Mail Security\n`;
    markdown_report += `| Techno | Enable | proof | \n| --- | --- | --- |\n`;
    markdown_report += `| SPF | ${mail_security.spf.enable} | ${mail_security.spf.records.join(', ')} |\n`;
    markdown_report += `| DMARC | ${mail_security.dmac.enable} | ${mail_security.dmac.records.join(', ')} |\n`;

    //console.log(JSON.stringify(open_ports, null, 2));

    fs.writeFileSync(`report.${domain}.md`, markdown_report);
    console.log(`{+} Report saved to report.${domain}.md`);
}

async function scan_ip(ip) {
    let markdown_report = `# Recon Report for ${domain}\n\n`;

    let categorized = await ip.categorize(iplist);
    console.log(`\n+-------------------------------------+`);
    console.log(`{+} Scan open ports for ${categorized.length} IPs\n`);
    let open_ports = await nmap.nmap(categorized);

    markdown_report += `\n\n`;
    markdown_report += `## Open Ports\n`;
    for (let ip of open_ports) {
        markdown_report += `### ${ip.ip}\n`;
        markdown_report += `| Port | Service | http server ? | \n| --- | --- | --- |\n`;
        ip.ports.forEach(port => {
            markdown_report += `| ${port.port} | ${port.service} | ${port.is_web_server ? "true" : "false"} |\n`;
        });
    }
    
    fs.writeFileSync(`report.${ip}.md`, markdown_report);
    console.log(`\n\n{+} Report saved to report.${ip}.md`);
}

async function main() {
    console.log(fs.readFileSync('./art/landing.art', 'utf8'));

    let args = process.argv.slice(2);
    if (args.includes('--url')) {
        let url = args[args.indexOf('--url') + 1];
        if (!url) {
            console.log('{+} Please provide a url');
            process.exit(1);
        }
        scan_domain(url);
    } else if (args.includes('--ip')) {
        let ip = args[args.indexOf('--ip') + 1];
        if (!ip) {
            console.log('{+} Please provide an ip');
            process.exit(1);
        }
        scan_ip(ip);
    } else {
        console.log('{+} Please provide a url or an ip');
        process.exit(1);
    }
}

main()