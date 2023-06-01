/* run with nodejs */

var fs = require('fs');
var vm = require('vm');

function include(path) {
		var code = fs.readFileSync(path, 'utf-8');
		vm.runInThisContext(code, path);
}

srcdir=process.env["srcdir"];
if (srcdir == undefined) {
	srcdir = ".";
}
builddir=process.env['builddir']
if (builddir == undefined) {
	builddir = ".";
}
include(builddir + "/gnutls-ciphers.js");
include(srcdir + "/registry-ciphers.js");


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

                if (cs.min_version !== "TLS1.3") {
		        if (cs.mac == "AEAD") {
			        if (kx + "-" + cipher != cs.gnutlsname && kx + "-" + cipher + "-SHA256" != cs.gnutlsname && kx + "-" + cipher + "-SHA384" != cs.gnutlsname) {
				        console.log("Broken AEAD ciphersuite: ", kx + "-" + cipher, " ", cs.gnutlsname);
				        process.exit(1);
			        }
                        } else if (kx + "-" + cipher + "-" + mac == "VKO-GOST-12-GOST28147-TC26Z-CNT-GOST28147-TC26Z-IMIT") {
                                if (cs.gnutlsname != "GOSTR341112-256-28147-CNT-IMIT") {
				        console.log("Broken ciphersuite name: ", kx + "-" + cipher + "-" + mac, " ", cs.gnutlsname);
				        process.exit(1);
                                }
                        } else {
			        if (kx + "-" + cipher + "-" + mac != cs.gnutlsname) {
				        console.log("Broken ciphersuite name: ", kx + "-" + cipher + "-" + mac, " ", cs.gnutlsname);
				        process.exit(1);
			        }
		        }
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
			if (cs.name !== "TLS_DHE_PSK_WITH_AES_128_CCM_8" &&
					cs.name !== "TLS_DHE_PSK_WITH_AES_256_CCM_8") {
				console.log("Name doesn't match official name for id:", cs.name, registry_ciphersuites[cs.id], cs.id);
				process.exit(1);
			}
		}
	}

	process.exit(0);

})();
