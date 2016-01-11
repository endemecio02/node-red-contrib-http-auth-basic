var os = require('os');
var fs = require('fs');
var crypto = require('crypto');
var bcrypt = require('bcrypt');
var md5 = require('apache-md5');
var crypt = require('apache-crypt');

module.exports = function(RED) {
	"use strict";

	function HttpAuthNode(config) {
		RED.nodes.createNode(this, config);

    var _node = this;
		var _realm = config.realm.trim();
		var _username = config.username.trim();
		var _password = config.password.trim();
    var _file = config.file.trim();
    var _users = {};

    inflate(_users, _file, function() {
			if (_username && _password) {
				_users[_username.toLowerCase()] = new User(_username, _password, true);
			}
		});

		this.on('input', function (msg) {
			var response = msg.res._res;
			var header = msg.req.get("Authorization");

			if (!header || !header.match(/^Basic\s/i)) {
				unauthorized(response, _realm);
			} else {
				var hash = header.substring(6).trim();
				var components = new Buffer(hash, 'base64').toString().split(":");
				var username = components[0] ? components[0].trim() : null;
				var password = components[1] ? components[1].trim() : null;

        authenticate(username, password, _users, function(isAuthenticated) {
        	isAuthenticated ? _node.send(msg) : unauthorized(response, _realm);
				});
      }
		});

		this.on("close", function() {
			// Called when the node is shutdown - eg on redeploy.
			// Allows ports to be closed, connections dropped etc.
			// eg: node.client.disconnect();
		});
	}

	RED.nodes.registerType("node-red-contrib-http-auth-basic", HttpAuthNode);
};

function User(username, password, isPlain) {
  var algo = null;
  var hash = null;

	if (isPlain) {
		algo = 'plain';
  } else if (password.match(/^\$2(a|b|y)\$/i)) {
    algo = 'bcrypt';
		hash = password.replace('$2b$', '$2a$');
    hash = password.replace('$2y$', '$2a$');
  } else if (password.match(/^\$apr1\$/i)) {
    algo = 'md5';
    hash = password;
  } else if (password.match(/^\{SHA\}/i)) {
    algo = 'sha1';
    hash = password.substring(5);
  } else {
		algo = 'crypt';
		hash = password;
	}

  return {
    "username": username,
    "password": password,
    "algo": algo,
    "hash": hash
  };
}

function inflate(users, file, callback) {
	callback = typeof callback === 'function' ? callback : function() {};
	if (!users || !file) {
		callback();
	} else {
  	fs.access(file, fs.F_OK, function(err) {
			if (err) {
				console.log('[HTTP Auth - Basic] File does not exist: "' + file + '"');
				callback();
			} else {
				fs.access(file, fs.R_OK, function(err) {
					if (err) {
						console.log('[HTTP Auth - Basic] You do not have read access: "' + file + '"');
						callback();
					} else {
      			fs.stat(file, function(err, stats) {
        			if (err) {
          			console.log('[HTTP Auth - Basic] Error: "' + file + '"');
          			console.log(err);
								callback();
        			} else if (!stats.isFile()) {
          			console.log('[HTTP Auth - Basic] Not a file: "' + file + '"');
								callback();
        			} else {
          			fs.readFile(file, 'utf8', function(err, data) {
            			if (err) {
              			console.log('[HTTP Auth - Basic] Error: "' + file + '"');
              			console.log(err);
										callback();
            			} else {
              			var lines = data.trim().split(os.EOL);
        						for (var index = 0; index < lines.length; index++) {
        							var components = lines[index].split(':');
        							var username = components[0] ? components[0].trim() : null;
        							var password = components[1] ? components[1].trim() : null;
                			if (username && password) {
                  			users[username.toLowerCase()] = new User(username, password);
                			}
              			}
										callback();
            			}
          			});
        			}
      			});
    			}
  			});
			}
		});
	}
}

function unauthorized(response, realm) {
	response.set('WWW-Authenticate', 'Basic realm="' + realm + '"');
	response.type('text/plain');
	response.status(401).send('401 Unauthorized');
}

function authenticate(username, password, users, callback) {
  callback = typeof callback === "function" ? callback : function(isAuthenticated) {};
  var user = users[username.toLowerCase()];

  if (!user) {
		callback(false);
	} else {
		if (user.algo == 'plain') {
			callback(password == user.password);
    } else if (user.algo == 'bcrypt') {
      bcrypt.compare(password, user.hash, function(err, res) {
        if (err) {
          console.log('[HTTP Auth - Basic] Error: ');
          console.log(err);
          callback(false);
        } else {
          callback(res);
        }
      });
    } else if (user.algo == 'md5') {
      callback(md5(password, user.hash) == user.hash);
    } else if (user.algo == 'sha1') {
      var sha1 = crypto.createHash('sha1');
      sha1.update(password);
      callback(sha1.digest().toString('base64') == user.hash);
    } else if (user.algo == 'crypt') {
      callback(crypt(password, user.hash) == user.password);
    } else {
			callback(false);
		}
  }
}
