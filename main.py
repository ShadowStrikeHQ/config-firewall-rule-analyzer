import argparse
import logging
import sys
import os
import re
try:
    import yaml
    from jsonschema import validate, ValidationError
except ImportError as e:
    print(f"Error: Missing dependencies. Please install them:\n  pip install PyYAML jsonschema")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class FirewallRuleAnalyzer:
    """
    A class to analyze firewall rules for redundancy, shadowed rules, and overly permissive rules.
    """

    def __init__(self, rule_file=None, rule_type=None):
        """
        Initializes the FirewallRuleAnalyzer.

        Args:
            rule_file (str, optional): The path to the firewall rule file. Defaults to None.
            rule_type (str, optional): The type of firewall (iptables, firewalld, pfctl). Defaults to None.
        """
        self.rule_file = rule_file
        self.rule_type = rule_type
        self.rules = []  # Store parsed firewall rules

    def load_rules(self):
        """
        Loads firewall rules from the specified file based on the firewall type.
        """
        if not self.rule_file:
            logging.error("No rule file specified.")
            raise ValueError("Rule file is required.")

        if not os.path.exists(self.rule_file):
            logging.error(f"Rule file not found: {self.rule_file}")
            raise FileNotFoundError(f"Rule file not found: {self.rule_file}")

        try:
            with open(self.rule_file, 'r') as f:
                rule_content = f.read()
        except IOError as e:
            logging.error(f"Error reading rule file: {e}")
            raise

        if self.rule_type == 'iptables':
            self.rules = self.parse_iptables_rules(rule_content)
        elif self.rule_type == 'firewalld':
            self.rules = self.parse_firewalld_rules(rule_content)
        elif self.rule_type == 'pfctl':
            self.rules = self.parse_pfctl_rules(rule_content)
        else:
            logging.error("Unsupported firewall type.")
            raise ValueError("Unsupported firewall type. Supported types are: iptables, firewalld, pfctl")

    def parse_iptables_rules(self, rule_content):
        """
        Parses iptables rules from the given content.  Simple parsing for demonstration purposes.

        Args:
            rule_content (str): The content of the iptables rule file.

        Returns:
            list: A list of parsed iptables rules.
        """
        rules = []
        for line in rule_content.splitlines():
            line = line.strip()
            if line.startswith('-A'):
                rules.append(line)
        return rules

    def parse_firewalld_rules(self, rule_content):
        """
        Parses firewalld rules from the given content.  Basic parsing, needs refinement for real use.

        Args:
            rule_content (str): The content of the firewalld rule file.

        Returns:
            list: A list of parsed firewalld rules.
        """
        # Note:  This is a simplified example.  firewalld uses XML, which should be parsed correctly for robust analysis.
        rules = []
        for line in rule_content.splitlines():
            line = line.strip()
            if line.startswith('<rule'):
                rules.append(line)
        return rules
    
    def parse_pfctl_rules(self, rule_content):
        """
        Parses pfctl rules from the given content. Simplified parsing.

        Args:
            rule_content (str): The content of the pfctl rule file.

        Returns:
            list: A list of parsed pfctl rules.
        """
        rules = []
        for line in rule_content.splitlines():
            line = line.strip()
            if line.startswith('pass') or line.startswith('block'):
                rules.append(line)
        return rules

    def analyze_rules(self):
        """
        Analyzes the loaded firewall rules for potential issues.
        """
        if not self.rules:
            logging.warning("No rules loaded. Please load rules before analyzing.")
            return []

        report = []
        # Redundancy Check (Simplified)
        seen_rules = set()
        for rule in self.rules:
            if rule in seen_rules:
                report.append(f"Redundant rule found: {rule}")
            else:
                seen_rules.add(rule)

        # Shadowed Rule Check (Simplified)
        # This is a placeholder.  Full shadowed rule detection requires more complex logic.
        for i in range(len(self.rules)):
            for j in range(i + 1, len(self.rules)):
                if self.is_shadowed(self.rules[i], self.rules[j]):
                    report.append(f"Rule {self.rules[i]} may be shadowed by rule {self.rules[j]}")

        # Overly Permissive Rule Check (Simplified)
        #  This is also a placeholder.  What constitutes "overly permissive" depends on policy.
        for rule in self.rules:
            if "any" in rule.lower() or "0.0.0.0/0" in rule.lower():
                report.append(f"Potentially overly permissive rule: {rule}")

        return report

    def is_shadowed(self, rule1, rule2):
        """
        Placeholder for shadowed rule detection.  Needs more sophisticated logic.
        For now, just checks if rule1 is a substring of rule2 (very naive).

        Args:
            rule1 (str): The first firewall rule.
            rule2 (str): The second firewall rule.

        Returns:
            bool: True if rule1 might be shadowed by rule2, False otherwise.
        """
        return rule1 in rule2

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Firewall Rule Analyzer")
    parser.add_argument("-f", "--file", dest="rule_file", required=True,
                        help="Path to the firewall rule file.")
    parser.add_argument("-t", "--type", dest="rule_type", required=True,
                        choices=['iptables', 'firewalld', 'pfctl'],
                        help="Type of firewall (iptables, firewalld, pfctl).")
    return parser


def main():
    """
    Main function to parse arguments, load rules, analyze them, and print the report.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        analyzer = FirewallRuleAnalyzer(rule_file=args.rule_file, rule_type=args.rule_type)
        analyzer.load_rules()
        report = analyzer.analyze_rules()

        if report:
            print("Firewall Rule Analysis Report:")
            for issue in report:
                print(f"- {issue}")
        else:
            print("No issues found in the firewall rules.")

    except ValueError as e:
        logging.error(f"Error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        logging.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Usage Example:
    # To run:
    # python main.py -f iptables_rules.txt -t iptables
    # Create dummy files:
    # echo "-A INPUT -j ACCEPT" > iptables_rules.txt
    # echo "<rule><accept/></rule>" > firewalld_rules.xml
    # echo "pass all" > pf_rules.conf
    # python main.py -f iptables_rules.txt -t iptables
    # python main.py -f firewalld_rules.xml -t firewalld
    # python main.py -f pf_rules.conf -t pfctl
    main()