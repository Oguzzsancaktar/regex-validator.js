var cbi_validators = {

	'integer': function () {
		return (this.match(/^-?[0-9]+$/) != null);
	},

	'uinteger': function () {
		return cbi_validators.integer.apply(this) && (this >= 0);
	},

	'float': function () {
		return !isNaN(parseFloat(this));
	},

	'ufloat': function () {
		return cbi_validators['float'].apply(this) && (this >= 0);
	},

	'ipaddr': function () {
		return cbi_validators.ip4addr.apply(this) ||
			cbi_validators.ip6addr.apply(this);
	},

	'ip4addr': function () {
		if (this.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\S+))?$/)) {
			return (RegExp.$1 >= 0) && (RegExp.$1 <= 255) &&
				(RegExp.$2 >= 0) && (RegExp.$2 <= 255) &&
				(RegExp.$3 >= 0) && (RegExp.$3 <= 255) &&
				(RegExp.$4 >= 0) && (RegExp.$4 <= 255) &&
				((RegExp.$6.indexOf('.') < 0)
					? ((RegExp.$6 >= 0) && (RegExp.$6 <= 32))
					: (cbi_validators.ip4addr.apply(RegExp.$6)))
				;
		}

		return false;
	},

	'ip6addr': function () {
		if (this.match(/^([a-fA-F0-9:.]+)(\/(\d+))?$/)) {
			if (!RegExp.$2 || ((RegExp.$3 >= 0) && (RegExp.$3 <= 128))) {
				var addr = RegExp.$1;

				if (addr == '::') {
					return true;
				}

				if (addr.indexOf('.') > 0) {
					var off = addr.lastIndexOf(':');

					if (!(off && cbi_validators.ip4addr.apply(addr.substr(off + 1))))
						return false;

					addr = addr.substr(0, off) + ':0:0';
				}

				if (addr.indexOf('::') >= 0) {
					var colons = 0;
					var fill = '0';

					for (var i = 1; i < (addr.length - 1); i++)
						if (addr.charAt(i) == ':')
							colons++;

					if (colons > 7)
						return false;

					for (var i = 0; i < (7 - colons); i++)
						fill += ':0';

					if (addr.match(/^(.*?)::(.*?)$/))
						addr = (RegExp.$1 ? RegExp.$1 + ':' : '') + fill +
							(RegExp.$2 ? ':' + RegExp.$2 : '');
				}

				return addr.match(/^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$/) != null;
			}
		}

		return false;
	},

	'port': function () {
		return cbi_validators.integer.apply(this) &&
			(this >= 0) && (this <= 65535);
	},

	'portrange': function () {
		if (this.match(/^(\d+)-(\d+)$/)) {
			var p1 = RegExp.$1;
			var p2 = RegExp.$2;

			return cbi_validators.port.apply(p1) &&
				cbi_validators.port.apply(p2) &&
				(parseInt(p1) <= parseInt(p2))
				;
		}
		else {
			return cbi_validators.port.apply(this);
		}
	},

	'macaddr': function () {
		return this.match(/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/) != null;
	},

	'host': function () {
		return cbi_validators.hostname.apply(this) ||
			cbi_validators.ipaddr.apply(this);
	},

	'hostname': function () {
		if (this.length <= 253)
			return (this.match(/^[a-zA-Z0-9]+$/) != null ||
				(this.match(/^[a-zA-Z0-9_][a-zA-Z0-9_\-.]*[a-zA-Z0-9]$/) &&
					this.match(/[^0-9.]/)));
		return false;
	},

	'network': function () {
		return cbi_validators.uciname.apply(this) ||
			cbi_validators.host.apply(this);
	},

	'wpakey': function () {
		var v = this;

		if (v.length === 64)
			return v.match(/^[a-fA-F0-9]{64}$/) != null;
		else
			return (v.length >= 8) && (v.length <= 63);
	},

	'wepkey': function () {
		var v = this;

		if (v.substr(0, 2) == 's:')
			v = v.substr(2);

		if ((v.length === 10) || (v.length === 26))
			return v.match(/^[a-fA-F0-9]{10,26}$/) != null;
		else
			return (v.length === 5) || (v.length === 13);
	},

	'uciname': function () {
		return this.match(/^[a-zA-Z0-9_]+$/) != null;
	},

	'range': function (min, max) {
		var val = parseFloat(this);
		if (!isNaN(min) && !isNaN(max) && !isNaN(val))
			return (val >= min) && (val <= max);

		return false;
	},

	'min': function (min) {
		var val = parseFloat(this);
		if (!isNaN(min) && !isNaN(val))
			return (val >= min);

		return false;
	},

	'max': function (max) {
		var val = parseFloat(this);
		if (!isNaN(max) && !isNaN(val))
			return (val <= max);

		return false;
	},

	'rangelength': function (min, max) {
		var val = '' + this;
		if (!isNaN(min) && !isNaN(max))
			return ((val.length >= min) && (val.length <= max));

		return false;
	},

	'minlength': function (min) {
		var val = '' + this;
		if (!isNaN(min))
			return (val.length >= min);

		return false;
	},

	'maxlength': function (max) {
		var val = '' + this;
		if (!isNaN(max))
			return val.length <= max;

		return false;
	},

	'or': function () {
		for (var i = 0; i < arguments.length; i += 2) {
			if (typeof arguments[i] != 'function') {
				if (arguments[i] == this)
					return true;
				i--;
			}
			else if (arguments[i].apply(this, arguments[i + 1])) {
				return true;
			}
		}
		return false;
	},

	'and': function () {
		for (var i = 0; i < arguments.length; i += 2) {
			if (typeof arguments[i] != 'function') {
				if (arguments[i] != this)
					return false;
				i--;
			}
			else if (!arguments[i].apply(this, arguments[i + 1])) {
				return false;
			}
		}
		return true;
	},

	'neg': function () {
		return cbi_validators.or.apply(
			this.replace(/^[ \t]*![ \t]*/, ''), arguments);
	},

	'list': function (subvalidator, subargs) {
		if (typeof subvalidator != 'function')
			return false;

		var tokens = this.match(/[^ \t]+/g);
		for (var i = 0; i < tokens.length; i++)
			if (!subvalidator.apply(tokens[i], subargs))
				return false;

		return true;
	},
	'phonedigit': function () {
		return (this.match(/^[0-9\*#!\.]+$/) != null);
	}
};
var cbi_validators_v2 = {


	

	'ssid':function (value) {
		return value.match("[A-z]{0,30}") != null;
	},
	'password':function (value) {
		return value.match(RegExp("^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})")) != null;
	},

	'integer': function (value) {
		return value.match(/^-?[0-9]+$/) != null;
	},

	'uinteger': function (value) {
		return cbi_validators.integer.apply(value) && (value >= 0);
	},

	'float': function (value) {
		return !isNaN(parseFloat(value));
	},

	'ufloat': function (value) {
		return cbi_validators['float'].apply(value) && (value >= 0);
	},

	'ipaddr': function (value) {
		return cbi_validators.ip4addr.apply(value) ||
			cbi_validators.ip6addr.apply(value);
	},

	'ip4addr': function (value) {
		if (value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\S+))?$/)) {
			return (RegExp.$1 >= 0) && (RegExp.$1 <= 255) &&
				(RegExp.$2 >= 0) && (RegExp.$2 <= 255) &&
				(RegExp.$3 >= 0) && (RegExp.$3 <= 255) &&
				(RegExp.$4 >= 0) && (RegExp.$4 <= 255) &&
				((RegExp.$6.indexOf('.') < 0)
					? ((RegExp.$6 >= 0) && (RegExp.$6 <= 32))
					: (cbi_validators.ip4addr.apply(RegExp.$6)));
		}
		return false;
	},

	'ip6addr': function (value) {
		if (value.match(/^([a-fA-F0-9:.]+)(\/(\d+))?$/)) {
			if (!RegExp.$2 || ((RegExp.$3 >= 0) && (RegExp.$3 <= 128))) {
				var addr = RegExp.$1;

				if (addr == '::') {
					return true;
				}

				if (addr.indexOf('.') > 0) {
					var off = addr.lastIndexOf(':');

					if (!(off && cbi_validators.ip4addr.apply(addr.substr(off + 1))))
						return false;

					addr = addr.substr(0, off) + ':0:0';
				}

				if (addr.indexOf('::') >= 0) {
					var colons = 0;
					var fill = '0';

					for (var i = 1; i < (addr.length - 1); i++)
						if (addr.charAt(i) == ':')
							colons++;

					if (colons > 7)
						return false;

					for (var i = 0; i < (7 - colons); i++)
						fill += ':0';

					if (addr.match(/^(.*?)::(.*?)$/))
						addr = (RegExp.$1 ? RegExp.$1 + ':' : '') + fill +
							(RegExp.$2 ? ':' + RegExp.$2 : '');
				}

				return (addr.match(/^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$/) != null);
			}
		}

		return false;
	},

	'personname': function (value) {
		return value.match(/^[a-zA-ZàáâäãåąčćçęèéêëėğıįìíîïłńòóôöõøşùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄĆČÇĖĘÈÉÊËĞÌÍÎÏĮİŁŃÒÓÔÖÕØŞÙÚÛÜŲŪŸÝŻŹÑßÇŒÆČŠŽ∂ð ,.'-]+$/u)!=null;
	},

	'mail': function (value) {
		return value.match(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
	},

	'port': function (value) {
		return cbi_validators.integer.apply(value) &&
			(value >= 0) && (value <= 65535);
	},

	'portrange': function (value) {
		if (value.match(/^(\d+)-(\d+)$/)) {
			var p1 = RegExp.$1;
			var p2 = RegExp.$2;

			return cbi_validators.port.apply(p1) &&
				cbi_validators.port.apply(p2) &&
				(parseInt(p1) <= parseInt(p2))
				;
		}
		else {
			return cbi_validators.port.apply(value);
		}
	},

	'macaddr': function (value) {
		return value.match(/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/) != null;
	},
	'macaddr_wildcard': function (value) {
		return value.match(/(^([a-fA-F0-9]{2}:){2}([a-fA-F0-9]{2})\*$)|^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/) != null;
	},

	'host': function (value) {
		return cbi_validators.hostname.apply(value) ||
			cbi_validators.ipaddr.apply(value);
	},

	'hostname': function (value) {
		if (value.length <= 253)
			return (value.match(/^[a-zA-Z0-9]+$/) != null ||
				(value.match(/^[a-zA-Z0-9_][a-zA-Z0-9_\-.]*[a-zA-Z0-9]$/) &&
					value.match(/[^0-9.]/)));

		return false;
	},

	'network': function (value) {
		return cbi_validators.uciname.apply(value) ||
			cbi_validators.host.apply(value);
	},

	'wpakey': function (value) {
		var v = value;

		if (v.length === 64)
			return v.match(/^[a-fA-F0-9]{64}$/) != null;
		else
			return (v.length >= 8) && (v.length <= 63);
	},

	'wepkey': function (value) {
		var v = value;

		if (v.substr(0, 2) == 's:')
			v = v.substr(2);

		if ((v.length === 10) || (v.length === 26))
			return (v.match(/^[a-fA-F0-9]{10,26}$/) != null);
		else
			return (v.length === 5) || (v.length === 13);
	},

	'uciname': function (value) {
		return (value.match(/^[a-zA-Z0-9_]+$/) != null);
	},

	'range': function (value, min, max) {
		var val = parseFloat(value);
		if (!isNaN(min) && !isNaN(max) && !isNaN(val)) {
			return (val >= min) && (val <= max);
		}
		return false;
	},
	'min': function (value, min) {
		var val = parseFloat(value);
		if (!isNaN(min) && !isNaN(val))
			return (val >= min);

		return false;
	},

	'max': function (value, max) {
		var val = parseFloat(value);
		if (!isNaN(max) && !isNaN(val))
			return val <= max;

		return false;
	},

	'rangelength': function (value, min, max) {
		var val = '' + value;
		if (!isNaN(min) && !isNaN(max))
			return (val.length >= min) && (val.length <= max);

		return false;
	},

	'minlength': function (value, min) {
		var val = '' + value;
		if (!isNaN(min))
			return val.length >= min;

		return false;
	},

	'maxlength': function (value, max) {
		var val = '' + value;
		if (!isNaN(max))
			return val.length <= max;

		return false;
	},

	'or': function (value) {
		for (var i = 0; i < arguments.length; i += 2) {
			if (typeof arguments[i] != 'function') {
				if (arguments[i] == value)
					return true;
				i--;
			}
			else if (arguments[i].apply(value, arguments[i + 1])) {
				return true;
			}
		}
		return false;
	},

	'and': function (value) {
		for (var i = 0; i < arguments.length; i += 2) {
			if (typeof arguments[i] != 'function') {
				if (arguments[i] != value)
					return false;
				i--;
			}
			else if (!arguments[i].apply(value, arguments[i + 1])) {
				return false;
			}
		}
		return true;
	},

	'neg': function (value) {
		return cbi_validators.or.apply(
			value.replace(/^[ \t]*![ \t]*/, ''), arguments);
	},

	'list': function (value, subvalidator, subargs) {
		if (typeof subvalidator != 'function')
			return false;

		var tokens = value.match(/[^ \t]+/g);
		for (var i = 0; i < tokens.length; i++)
			if (!subvalidator.apply(tokens[i], subargs))
				return false;

		return true;
	},

	'phonedigit': function (value) {
		return (value.match(/^[0-9\*#!\.]+$/) != null);
	},
	'phonenumber': function (value) {
		return value.length>5 && (value.match(/^[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$/) != null);
	},
	'iban': function (value) {
		return (value.match(/\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9]{4}){4}(?!(?:[ ]?[0-9]){3})(?:[ ]?[0-9]{1,2})?\b/) != null);
	},
	'regex': function (value, regex, mustExactMatch=true) {		
		var match = value.match(regex);
		var isMatch=match && (mustExactMatch? value === match[0]:value.indexOf(match[0])>-1);
		return isMatch;
	},
	'url': function (value) {
		var res = value.match(/(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/g);
		if (res == null)
			return false;
		else if (res == value)
			return true;
	},
	'iprangecollision': function (IP, networkInfoObject, dhcpID, startIP) {
		if (networkInfoObject != null) {
			if (networkInfoObject.DHCP != null) {
				if (networkInfoObject.DHCP.LAN != null) {
					if (networkInfoObject.DHCP.LAN.length > 0) {
						for (var i = 0; i < networkInfoObject.DHCP.LAN.length; i++) {
							if (networkInfoObject.DHCP.LAN[i] != null) {
								if (typeof (networkInfoObject.DHCP.LAN[i].startipaddress) != 'undefined') {
									if (networkInfoObject.DHCP.LAN[i].startipaddress != null) {
										if (networkInfoObject.DHCP.LAN[i].id != dhcpID) {   //exclude self
											if (IsInIPRange([networkInfoObject.DHCP.LAN[i].startipaddress, networkInfoObject.DHCP.LAN[i].endipaddress], IP)) { return false; }
											if (typeof startIP != 'undefined') {
												if (startIP != null) {
													if (startIP.split(".").length === 4) {
														var sIP = ConvertIPAddressToInteger(startIP);
														var ip = ConvertIPAddressToInteger(IP);
														var startipaddress = ConvertIPAddressToInteger(networkInfoObject.DHCP.LAN[i].startipaddress);
														var endipaddress = ConvertIPAddressToInteger(networkInfoObject.DHCP.LAN[i].endipaddress);
														if (sIP < startipaddress && sIP < endipaddress) {
															if (ip < startipaddress && ip < endipaddress) { if (sIP > ip) { alert("EndIP address must not be smaller than StartIP"); } } else { return false; }
														}
														else if (sIP > startipaddress && sIP > endipaddress) {
															if (ip > startipaddress && ip > endipaddress) { if (sIP > ip) { alert("EndIP address must not be smaller than StartIP"); } } else { return false; }
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		return true;
	}
}

function ConvertIPAddressToInteger(IP) {
	var ipInteger = 0;
	var parts = IP.split(".").reverse();
	for (var i = 0; i < parts.length; i++) {
		ipInteger += parts[i] * (Math.pow(256, i));
	}
	return ipInteger;
}

function IsInIPRange(IPRange, IP) {
	if (IPRange.length === 2) {  //startIP,endIP
		var sIP = IPRange[0];
		sIP = ConvertIPAddressToInteger(sIP);
		var eIP = IPRange[1];
		eIP = ConvertIPAddressToInteger(eIP);
		IP = ConvertIPAddressToInteger(IP);
		if ((IP < sIP && IP < eIP) || (IP > sIP && IP > eIP)) { return false; }
	}
	return true;
}
