from executor import Executor
from watchguard_parser import *
from watchguard_command_generator import WatchguardCommandGenerator
from decouple import config
from rule import Rule, NetworkPeer, NetworkService, RuleFilter


class RuleManager:

    def __init__():
        ...

    def add_rules():
        ...
    
    def del_rules():
        ...

    def read_managed_rules():


def main():
    device_cfg = {
        "device_type": "watchguard_fireware",
        "ip": config('ROUTER_IP'),
        "port": config('ROUTER_PORT', default=4118, cast=int),
        "username": config('ROUTER_USERNAME'),
        "password": config('ROUTER_PASSWORD'),
        }
    
    address = [NetworkPeer(ip_low='10.1.1.2'), NetworkPeer(ip_low='20.2.2.2')]
    services = (NetworkService(protocol='icmp'),)
    owners = ('o1',)
    rule = Rule(sources=address, destinations=address, filter=services, owners=owners)

    command_generator = WatchguardCommandGenerator()
    print(command_generator.add_rule(rule))
    print(command_generator.add_filter(rule.filter))
    result=''
    with Executor(device_cfg) as executor:
        
        for command in command_generator.add_filter(rule.filter):
            print(command)
            print(executor.execute(command))

        for command in command_generator.add_rule(rule):
            print(command)
            print(executor.execute(command))

        result=executor.execute(command_generator.read_rules())
        
        parser = WatchguardParser()
        names = parser.extract_rule_names(result)
        rules_without_filters = []
        for name in names:
            rules_without_filters.append(parser.parse_rule(executor.execute(command_generator.read_rule(name))))
        
        rules = []
        for rule in rules_without_filters:
            rules.append(rule)
            rules[-1]['filter'] = parser.parse_filter(executor.execute(command_generator.read_filter(rule['filter_name'])))
            del(rules[-1]['filter_name'])
        
        for rule in rules:
            print(rule)

main()

