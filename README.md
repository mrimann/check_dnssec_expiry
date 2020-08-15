# check_dnssec_expiry - Icinga / Nagios Plugin to validate DNSSEC of a DNS-Zone

Goal of this plugin is to monitor DNSSEC validation for a given zone using a DNSSEC validating resolver.

It covers the following cases:

- Resolver that doesn't validate DNSSEC signatures: emits a WARNING since the environment for the other check is broken and needs to be fixed first (which doesn't imply the signatures of that zone to be broken). This test is executed against the zone `dnssec-failed.org` but you can override this and provide your own always-failing zone
- Unsigned zones: will emit a WARNING, as we expect this check to only be actively executed against DNSSEC enabled/signed zones
- Broken signature: will emit a CRITICAL, independent of whether the zone could be resolvable on a resolver without DNSSEC validation
- Expiry date of the RRSIG answer: the remaining lifetime is calculated and depending on the remaining % of the total lifetime, an alert can be generated
  - emits a CRITICAL if the remaining time is lower than `-w`
  - emits a WARNING if the remaining time is lower than `-c`
  - emits an OK if none of the above match
- If there are multiple RRSIG entries with overlapping validity time-frames, we're fine, if at least one of them fulfills the minimum remaining lifetime check
- is configurable via command line options, see table below


## Installation (Icinga):

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


## Installation (Icinga2):
Clone this repository into the directory where you have all your other plugins, for Icinga on Ubuntu, this is probably `/usr/lib/nagios/plugins` but could be somewhere else on your system:

	cd /usr/lib/nagios/plugins
	git clone https://github.com/mrimann/check_dnssec_expiry.git

To add the command check to your Icinga2 installation, first add the following command definition e.g. to `/etc/icinga2/conf.d/commands.conf`:

	# 'check_dnssec_expiry' command definition
	object CheckCommand "dnssec_expiry" {
      import "plugin-check-command"
      command = [ PluginDir + "/check_dnssec_expiry.sh" ]

      arguments = {
        "-z" = {
         required = true
         value = "$zone$"
         }
       "-w" = "$dnssec_warn$"    // Default = 10d
       "-c" = "$dnssec_crit$"    // Default = 5d
       "-r" = "$resolver$"       // Default = 8.8.8.8
       "-f" = "$failing$"        // Sets the always failing domain (to verify function of resolver). Default = dnssec-failed.org
      }
    }

Then add a service definition e.g. to `/etc/icinga2/conf.d/services.conf`:

    apply Service "dnssec" for (zone in host.vars.dnssec_zones) {
        import "generic-service"
        vars.zone = zone
        vars.resolver = "127.0.0.1"
        display_name = "DNSSEC signature expiring"
        check_command = "dnssec_expiry"
        }

And finally, add a list of the zones to be checked to the hosts definition e.g. `/etc/icinga2/conf.d/hosts.conf`:

    /* DNSSEC checks -- https://github.com/mrimann/check_dnssec_expiry */
    vars.dnssec_zones = ["zone1", "zone2", "zone3" ]

In the above snippet, replace zone1, zone2, zone3 with the zones to be checked.
You can set vars.resolver to the address of a resolver to use, etc.

**Please adapt the above snippets to your needs!!!** (and refer to the documentation of your monitoring system for further details).

## Installation (Zabbix external check)

The script can also be used as-is as a data source for a Zabbix server external checks.

 * save `check_dnssec_expiry.sh` to `/usr/local/bin`
 * create wrapper scripts in the directory where Zabbix expects external scripts ( `/usr/lib/zabbix/externalscripts` ), replace `2620:fe::fe` with the IP of the validating resolver of your preference.
  * `zext_dnssec_sig_percentage.sh`:

  ```bash
    #!/bin/bash
    /usr/local/bin/check_dnssec_expiry.sh -z $1 -r 2620:fe::fe | gawk 'match($$0, /sig_lifetime_percentage=([0-9]+)[^0-9]/, b) {print b[1]}'
  ```

  * `zext_dnssec_sig_seconds.sh`:

  ```bash
  #!/bin/bash
  /usr/local/bin/check_dnssec_expiry.sh -z $1 -r 2620:fe::fe | gawk 'match($$0, /sig_lifetime=([0-9]+)\s/, a) {print a[1]}'
  ```

 * Verify that the scripts are working and returning an integer (percentage or remaining seconds).
 ```
 /usr/lib/zabbix/externalscripts/zext_dnssec_sig_percentage.sh switch.ch
 98
 /usr/lib/zabbix/externalscripts/zext_dnssec_sig_seconds.sh switch.ch
 2010539
 ```
 * In the Zabbix GUI, create a template `DNSSEC signature expiration` and define external check items:
  * `zext_dnssec_sig_seconds.sh[{HOSTNAME}]` (Numeric unsigned, Units `s`)
  * `zext_dnssec_sig_percentage.sh[{HOSTNAME}]` (Numeric unsigned)


 * Define Triggers/Alerts as usual, for example:

  `{Template DNSSEC signature expiration:zext_dnssec_sig_seconds.sh[{HOSTNAME}].last(#2)}<2d`

  to alert when the remaining signature lifetime falls below 2 days.

## Command Line Options:

| Option | Triggers what? | Mandatory? | Default value |
| --- | --- | --- | --- |
| -h | Renders the help / usage information | no | n/a |
| -z | Sets the zone to validate, e.g. "example.org" | yes | n/a |
| -w | Sets the warning percentage value regarding the remainig lifetime of the signature in percent (%), days (d), hours (h), minutes (m) or seconds (s) | no | 10d |
| -c | Sets the critical percentage value regarding the remainig lifetime of the signature in percent (%), days (d), hours (h), minutes (m) or seconds (s) | no | 5d |
| -r | Sets the resolver to use | no | 8.8.8.8 |
| -f | Sets the always failing domain (used to verify the proper function of the resolving server | no | dnssec-failed.org |
| -t | Sets the DNS record type to validate, e.g. "A" | no | SOA |


## TODO:

Well, it needs some serious testing to be honest - please provide feedback on whether the plugin helped and in which environment you tested it.


## How to contribute?

Feel free to [file new issues](https://github.com/mrimann/check_dnssec_expiry/issues) if you find a problem or to propose a new feature. If you want to contribute your time and submit an improvement, I'm very eager to look at your pull request!

In case you want to discuss a new feature with me, just send me an [e-mail](mailto:mario@rimann.org).


### Contributors
Thanks for your support! (in chronological order)
- André Keller from [VSHN](www.vshn.ch)
- Oli Schacher from [Switch CERT](http://www.switch.ch/)
- Jan-Piet Mens [www.jpmens.net](http://jpmens.net/)
- Warren Kumari
- Rob J. Epping
- Thushjandan Ponnudurai
- Fabian Fröhlich [f-froehlich.de](https://f-froehlich.de/)

## License

Licensed under the permissive [MIT license](http://opensource.org/licenses/MIT) - have fun with it!

### Can I use it in commercial projects?

Yes, please! And if you save some of your precious time with it, I'd be very happy if you give something back - be it a warm "Thank you" by mail, spending me a drink at a conference, [send me a post card or some other surprise](http://www.rimann.org/support/) :-)
