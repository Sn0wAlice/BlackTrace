const xml2js = require('xml2js');
const http = require('http');
const https = require('https');
const {
  exec
} = require('child_process');

exports.nmap = async function (ips_categorized) {
  let open_ports = [];

  // get process args
  let args = process.argv.slice(2);
  if (args.includes('--skip-nmap')) {
    console.log(`{+} Skipping nmap scan`);
    return open_ports;
  }

  for (const d of ips_categorized) {
    switch (d.category) {
      case "unknown": {
        console.log(`{+} Scanning ${d.ip} for open ports`);
        let ports = await scanOpenPorts(d.ip);

        for (const port of ports.openPorts) {
          let is_web_server = await isWebServer(d.ip, port.port, port.protocol === 'https');
          if (is_web_server) {
            console.log(`{+} ${d.ip}:${port.port} is a web server`);
            port.is_web_server = true;
          } else {
            port.is_web_server = false;
          }
        }

        open_ports.push({
          ip: d.ip,
          ports: ports.openPorts
        });
        break;
      }
      case "cloudflare": {
        console.log(`{+} Skipping ${d.ip} because it is a Cloudflare IP`);
        break;
      }
      default: {
        break;
      }
    }
  }

  return open_ports;
}


async function scanOpenPorts(target) {
  // Nmap command to scan for open ports and output in JSON format
  const nmapCommand = `nmap -p- --open -oX - ${target}`;

  return new Promise((resolve, reject) => {
    exec(nmapCommand, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }
      if (stderr) {
        console.error(`Stderr: ${stderr}`);
        return;
      }

      // Convert XML output to JSON
      xml2js.parseString(stdout, (err, result) => {
        if (err) {
          console.error('Error parsing XML:', err);
          return;
        }

        const ports = [];
        const host = result.nmaprun.host[0];
        if (host.ports && host.ports[0].port) {
          host.ports[0].port.forEach((port) => {
            if (port.state[0].$.state === 'open') {
              ports.push({
                port: parseInt(port.$.portid, 10),
                protocol: port.$.protocol,
                service: port.service ? port.service[0].$.name : 'unknown',
              });
            }
          });
        }

        const report = {
          target: target,
          openPorts: ports,
        };

        return resolve(report);
      });
    });
  });
}

async function isWebServer(ip, port, useHttps = false) {
  return new Promise((resolve) => {
    const options = {
      host: ip,
      port: port,
      method: 'GET',
      timeout: 10000,
      path: '/'
    };

    const protocol = useHttps ? https : http;

    const req = protocol.request(options, (res) => {
      // If we get a response with status code, assume it's a web server
      resolve(true);
      req.destroy();
    });

    req.on('error', (err) => {
      resolve(false);
    });

    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });

    req.end();
  });
}