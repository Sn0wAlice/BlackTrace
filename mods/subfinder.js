const fetch = require('node-fetch');

function merge(array1, array2) {
    let c = array1.concat(array2);
    // remove duplicates
    return [...new Set(c)];
}

function remove_stars(array) {
    return array.filter((x) => !x.includes("*"));
}

exports.subfinder =  async function (domain) {
    let tmp_subdomain_finder = []

    let crt_sh = await ask_to_crt_sh(domain);
    tmp_subdomain_finder = merge(tmp_subdomain_finder, crt_sh)

    // add more here

    console.log(`{+} Purging subdomains`);
    tmp_subdomain_finder = remove_stars(tmp_subdomain_finder)
    return tmp_subdomain_finder
}



async function ask_to_crt_sh(domain) {
    console.log(`{+} Asking crt.sh for subdomains of ${domain}`);
    let url = `https://crt.sh/?q=${domain}&output=json`;
    let res = await fetch(url);
    let data = await res.json();
    // filter out subdomains
    let subdomains = data.map((d) => d.name_value);
    // domain can contain \n. in that case, split it
    let new_subdomains = [];
    subdomains.forEach((sub) => {
        if (sub.includes("\n")) {
            let tmp = sub.split("\n");
            new_subdomains = merge(new_subdomains, tmp);
        } else {
            new_subdomains.push(sub);
        }
    });
    return new_subdomains;
}

