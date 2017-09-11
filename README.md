# check_dnssec_expiry - Icinga / Nagios Plugin to validate DNSSEC of a DNS-Zone

Goal of this plugin is to enable DNSSEC validation for a given zone, based on a DNSSEC validation resolver.

It covers the following cases:

- Resolver that doesn't validate DNSSEC signatures: emits a WARNING since the environment for the other check is broken and needs to be fixed first (which doesn't imply the signatures of that zone to be broken). This test is executed against the zone `dnssec-failed.org` but you can override this and provide your own always-failing zone
- Unsigned zones: will emit a WARNING, as we expect this check to only be actively executed against DNSSEC enabled/signed zones
- Broken signature: will emit a CRITICAL, independent of whether the zone could be resolvable on a resolver without DNSSEC validation
- Expiry date of the RRSIG answer: the remaining lifetime is calculated and depending on the remaining % of the total lifetime, an alert can be generated
  - emits a CRITICAL if the remaining percentage is < 10%
  - emits a WARNING if the remaining percentage is < 20%
  - emits an OK if none of the above match
- If there are multiple RRSIG entries with overlapping valitity time-frames, we're fine, if at least one of them fulfills the minimum remaining lifetime check
- is configurable via command line options, see table below


## Installation:

Clone this repository into the directory where you have all your other plugins, for Icinga on Ubuntu, this is probably `/usr/lib/nagios/plugins` but could be somewhere else on your system:

	cd /usr/lib/nagios/plugins
	git clone https://github.com/mrimann/check_dnssec_expiry.git

To add the check to your Icinga installation, first add the following command definition e.g. to `/etc/icinga/objects/commands.cfg`:

	# 'check_dnssec_expiry' command definition
	define command {
		command_name	check_dnssec_expiry
		command_line    $USER1$/check_dnssec_expiry/check_dns_expiry.sh -z $ARG1$ -r $ARG2$ -f $ARG3$
	}

And second, add a service definiton *per zone* to e.g. `/etc/icinga/objects/services.cfg`:

	define service {
		use			critical-service
		name			check_dnssec_expiry ZONE
		description		DNSSEC ZONE
		host_name		NAMESERVER
		check_command		check_dnssec_expiry!ZONE
		normal_check_interval	60
		retry_check_interval	5
	}


In the above snippet, replace ZONE with the zone to be checked, e.g. "example.org" and NAMESERVER with your Nameserver (basically it doesn't matter since the check is executed on the Icinga host itself in this basic setup).

**Please adapt the above snippets to your needs!!!** (and refer to the documentation of your monitoring system for further details)



## Command Line Options:

| Option | Triggers what? | Mandatory? | Default value |
| --- | --- | --- | --- |
| -z | Sets the zone to validate, e.g. "example.org" | yes | n/a |
| -w | Sets the warning percentage value regarding the remainig lifetime of the signature | no | 20 |
| -c | Sets the critical percentage value regarding the remainig lifetime of the signature | no | 10 |
| -r | Sets the resolver to use | no | 8.8.8.8 |
| -f | Sets the always failing domain (used to verify the proper function of the resolving server | no | dnssec-failed.org |


## TODO:

Well, it needs some serious testing to be honest - please provide feedback on whether the plugin helped and in which environment you tested it.


## How to contribute?

Feel free to [file new issues](https://github.com/mrimann/check_dnssec_expiry/issues) if you find a problem or to propose a new feature. If you want to contribute your time and submit an improvement, I'm very eager to look at your pull request!

In case you want to discuss a new feature with me, just send me an [e-mail](mailto:mario@rimann.org).

## License

Licensed under the permissive [MIT license](http://opensource.org/licenses/MIT) - have fun with it!

### Can I use it in commercial projects?

Yes, please! And if you save some of your precious time with it, I'd be very happy if you give something back - be it a warm "Thank you" by mail, spending me a drink at a conference, [send me a post card or some other surprise](http://www.rimann.org/support/) :-)
