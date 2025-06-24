from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import rule_manager_protocol
from rule import NamedRule, RulePeer
from ipaddress import ip_address, ip_network
from contextlib import contextmanager
from decouple import config
import re

class WatchGuardRuleManager():
    """RuleManagerm class for managing WatchGuard Firebox firewall rules."""

    def __init__(self):
        """Initialize the rule manager with WatchGuard connection parameters."""
        self._queue: Union[NamedRule, str] = {}
        self.connection = None 
        self._watchguard = {
            'device_type': 'watchguard_fireware',
            'ip': config("ROUTER_IP"),
            'port': config("ROUTER_PORT", default = 4118, cast=int),         
            'username': config("ROUTER_USERNAME"),
            'password': config("ROUTER_PASSWORD")
        }

    def connect(self):
        """Establish connection and store as self.connection"""
        if self.connection is None:
            self.connection = ConnectHandler(**self._watchguard)

    def disconnect(self):
        """Close connection if open"""
        if self.connection:
            self.connection.send_command(f'exit', expect_string = "")
            self.connection.disconnect()
            self.connection = None

    @contextmanager
    def session(self):
        self.connect()
        try:
            yield
        finally:
            self.disconnect()

            
    def _create_rule_peer(self,field: str):
        split = field.split('-')
        
        if len(split) == 1:
            # Could be a single IP or a network (CIDR)
            ip_str = split[0].strip()
            try:
                ip_net = ip_network(ip_str, strict=False)
                return RulePeer(ip_low=ip_net, ip_high=None)
            except ValueError:
                # Not a network, try as single IP
                ip_addr = ip_address(ip_str)
                return RulePeer(ip_low=ip_addr, ip_high=None)
    
        elif len(split) == 2:
            # IP range: low and high IPs
            ip_low = ip_address(split[0])
            ip_high = ip_address(split[1])
            return RulePeer(ip_low=ip_low, ip_high=ip_high)
    
        else:
            raise ValueError(f"Invalid IP range format: {field}")


    def _get_filter(self,rules: list[dict]):
        for rule in rules:
            old_filter = rule['filter']
            rule['filter'] = self.connection.send_command(f'show policy-type '+ old_filter)


    def _create_rule(self,fields: list[str]):
        rule = {
            'identifier': fields[2],
            'filter': fields[3],
            'sources': [self._create_rule_peer(f) for f in fields[4]],
            'destinations': [print(f) for f in fields[5]],
        }
        return rule
        

    def _extract_rules_from_string(self,rules_output: str):
        lines = rules_output.splitlines()
        output = []
        rules = []
        for line in lines: 
                parts = line.split('\t')
                first_part  = parts[0].split()
                second_part = [p.strip() for p in parts[1:]]
                rules.append(first_part + second_part)
        
        ip_lists = []

        for rule in rules:
            if len(rule) == 3 :
                ip_lists.append(rule)

            if len(rule) == 8 :
                if isinstance(rule[4], str):
                    rule[4] = [rule[4].strip()]

                if isinstance(rule[5], str):
                    rule[5] = [rule[5].strip()]
                
                if re.match('test*',rule[2]):
                    for ip in ip_lists:
                        
                        if ip[0]:
                            rule[4].append(ip[0])
                        
                        if ip[1]:
                            rule[5].append(ip[1])
                    
                    output.append(self._create_rule(rule))
                ip_lists = []
        return output


    def read_all_rules(self) -> list[Rule]:
        """Retrieve all firewall rules managed by the manager.

        Returns:
            list[Rule]: A copy of policies and rules on firewall represented as a list or Rule objects.
        """
        try:
            with self.session():
                rules_output = self.connection.send_command(f'show rule')
                rules_without_filter = self._extract_rules_from_string(rules_output)
        except NetmikoTimeoutException as e:
            print(f"SSH connection timed out: {e}")
            raise
        except NetmikoAuthenticationException as e:
            print(f"Authentication failed: {e}")
            raise
        except Exception as e:
            print(f"Failed to read all rules: {e}")
            raise       



def main():
    """Example usage of WatchGuardSSHClient."""
    try:
        router = WatchGuardRuleManager()
        router.read_all_rules()
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
