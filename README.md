# config-Firewall-Rule-Analyzer
A command-line tool that parses firewall rules (iptables, firewalld, pfctl) from a specified file or system and analyzes them for redundancy, shadowed rules, and overly permissive rules. Outputs a report highlighting potential issues. - Focused on Tools for verifying that system or application configurations adhere to security best practices and policies. Scans configuration files, databases, or APIs for misconfigurations and vulnerabilities.

## Install
`git clone https://github.com/ShadowStrikeHQ/config-firewall-rule-analyzer`

## Usage
`./config-firewall-rule-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-f`: Path to the firewall rule file.
- `-t`: No description provided

## License
Copyright (c) ShadowStrikeHQ
