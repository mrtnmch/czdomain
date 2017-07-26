# CZ.NIC checker

A tool to check availability of .cz domains. It parses **nic.cz whois checker** instead of the *whois* tool which is quite limited (only a couple of queries/min).

## Features
- simple
- checks if a domain is free or prints its expiration date
- batch queries (1 second politeness factor)
- interactive mode
- there's a captcha after certain number of queries – in that case it shows warning and waits until you dismiss it (the captcha limit is IP based so you can do it in your browser)

**Important**: do not turn off the 1 second timeout (politeness). Don't be evil.
