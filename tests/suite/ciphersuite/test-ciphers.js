/* run with nodejs */

var fs = require('fs');
var vm = require('vm');

function include(path) {
    var code = fs.readFileSync(path, 'utf-8');
    vm.runInThisContext(code, path);
}

include('./gnutls-ciphers.js');
include('./registry-ciphers.js');


(function() {
//  var s = "NORMAL:-VERS-SSL3.0:-CIPHER-ALL:-SHA1:-MD5:+SHA1:+AES-256-GCM:+AES-256-CBC:+CAMELLIA-256-CBC:%SERVER_PRECEDENCE";
//  console.log("Test: ", require('util').inspect(priority_config(priority(s)), false, 10));
//  console.log("Test: ", require('util').inspect(priority_ciphersuites(priority(s)), false, 10));

  // check whether gnutls ciphersuite names match the kx/cipher/mac/prf combination
  for (var i in gnutls_ciphersuites) {
    if (!gnutls_ciphersuites.hasOwnProperty(i)) continue;
    var cs = gnutls_ciphersuites[i];
    var mac = cs.mac;
    if (mac == "AEAD") mac = cs.prf.replace("DIG-", "");
    mac = mac.replace("UMAC-", "UMAC");
    var cipher = cs.cipher.replace("3DES-CBC", "3DES-EDE-CBC");
    var kx = cs.kx.replace("ANON-DH", "DH-ANON").replace("ANON-ECDH", "ECDH-ANON").replace("SRP", "SRP-SHA");
    if (kx + "-" + cipher + "-" + mac != cs.gnutlsname) {
      console.log("Broken: ", kx + "-" + cipher + "-" + mac, " ", cs.gnutlsname);
    }
    if (cs.name !== i) {
      console.log("Name doesn't match index:", cs.name, i);
      process.exit(1);
    }
    if (!registry_ciphersuites[cs.id]) {
      if (cipher.match(/SALSA20/)) {
        var warned_salsa20;
        if (!warned_salsa20) {
          /* warn only once */
          console.log("Unofficial SALSA20 ciphers");
          warned_salsa20 = 1;
        }
      } else {
        console.log("Unofficial cipher:", cs.name, cs.id);
      }
    } else if (registry_ciphersuites[cs.id] !== cs.name) {
      console.log("Name doesn't match official name for id:", cs.name, registry_ciphersuites[cs.id], cs.id);
      process.exit(1);
    }
  }
  
  process.exit(0);

})();
