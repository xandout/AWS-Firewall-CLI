import cmd

import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate

from IPRule import IPRule


class AWSShell(cmd.Cmd):
    # intro = 'Welcome to the AWS SG Shell.   Type help or ? to list commands.\n'
    prompt = '(aws) '

    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None, region_name='us-east-1'):
        cmd.Cmd.__init__(self)
        self.region_name = region_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        if aws_access_key_id is None and aws_secret_access_key is None:
            self.aws_session = boto3.Session(region_name=region_name)
        else:
            self.aws_session = boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=self.region_name
            )
        self.regions = self.aws_session.get_available_regions('ec2')
        self.setprompt(self.region_name)

    def setprompt(self, arg):
        self.prompt = "({}) ".format(arg)

    def help_set(self):
        print("set region <region>\t\tSets the current region. Must be an AWS region name")

    def do_set(self, arg):
        parsed = parse(arg)
        item = parsed[0]
        to_pass = None
        if len(parsed) > 1:
            to_pass = parsed[1:]
        try:
            getattr(self, "set_" + item)(to_pass)
        except Exception as e:
            print "*** {} - Unknown item ***\n{}".format(item, e)

    def set_region(self, arg):
        if arg[0] in self.regions:
            self.__init__(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=arg[0]
            )
        else:
            print("Invalid region name '{}'. ".format(arg[0]))
            print("\nValid regions are {}".format("\n\t".join(self.regions)))

    def do_EOF(self, line):
        print "\n"
        return True

    def emptyline(self):
        pass

    def help_show(self):
        print("show groups\t\t\t\tShows all security groups in the current region.")
        print("show rules <group-id>\t\tShows all inbound rules in the specified group.")

    def do_show(self, arg):
        parsed = parse(arg)
        item = parsed[0]
        to_pass = None
        if len(parsed) > 1:
            to_pass = parsed[1:]
        try:
            getattr(self, "show_" + item)(to_pass)
        except Exception as e:
            print "*** {} - Unknown item ***\n{}".format(item, e)

    def show_groups(self, arg):
        sgs = self.aws_session.client('ec2').describe_security_groups()['SecurityGroups']
        headers = ['Group ID', 'Group Name', 'Rules Count']
        rows = []
        for g in sgs:
            l = [len(x['IpRanges']) for x in g['IpPermissions']] or [0]  # Handle empty groups
            rules_count = l[0]
            rows.append([g['GroupId'], g['GroupName'], rules_count])
        print tabulate(rows, headers=headers)

    def show_rules(self, arg):
        if len(arg) < 1 or len(arg) > 1:
            print "Please specify 1 group ID"
            pass
        perms = self.aws_session.resource('ec2').SecurityGroup(arg[0]).ip_permissions
        headers = ['Protocol', 'Port(s)', 'CIDR']
        rows = []
        for p in perms:
            if 'FromPort' not in p:
                p['FromPort'] = 'all'
            if 'ToPort' not in p:
                p['ToPort'] = 'all'
            if p['IpProtocol'] == '-1':
                p['IpProtocol'] = 'all'
            port_range = "{} - {}".format(p['FromPort'], p['ToPort'])
            if p['FromPort'] == p['ToPort']:
                port_range = p['FromPort']
            iprs = [ipr for ipr in p['IpRanges']]
            r = [[p['IpProtocol'], port_range, x['CidrIp']] for x in iprs]
            rows.extend(r)
        print tabulate(rows, headers=headers)

    def help_add(self):
        print("add rule <group-id> <cidr> <protocol> <port-range>\t\tAdds an inbound rule to the specified group.")
        print("Example: add rule sg-1234567 192.168.1.42/32 6 80")
        print("Example: add rule sg-1234567 192.168.1.42/32 tcp all")
        print("Example: add rule sg-1234567 192.168.1.42/32 icmp all")
        print("Example: add rule sg-1234567 0.0.0.0/0 all all")

    def help_del(self):
        print("del rule <group-id> <cidr> <protocol> <port-range>\t\tRemoves an inbound rule from the specified group.")
        print("Example: del rule sg-1234567 192.168.1.42/32 6 80")
        print("Example: del rule sg-1234567 192.168.1.42/32 tcp all")
        print("Example: del rule sg-1234567 192.168.1.42/32 icmp all")
        print("Example: del rule sg-1234567 0.0.0.0/0 all all")

    def do_add(self, arg):
        parsed = parse(arg)
        item = parsed[0]
        to_pass = None
        if len(parsed) > 1:
            to_pass = parsed[1:]
        try:
            getattr(self, "add_" + item)(to_pass)
        except Exception as e:
            print "*** {} - Unknown item ***\n{}".format(item, e)

    def add_rule(self, arg):
        # Need to do some validation
        group = arg[0]
        rule = IPRule(arg[1], arg[3], arg[2])
        # cidr = arg[1]
        # protocol = arg[2]
        # ports = [arg[3]]
        # if arg[3] != "-1":
        #     ports = arg[3].split('-')
        # from_port = ports[0]
        # to_port = ports[1] if len(ports) > 1 else ports[0]
        sg = self.aws_session.resource('ec2').SecurityGroup(group)
        try:
            sg.authorize_ingress(
                IpProtocol=rule.protocol,
                FromPort=rule.ports['FromPort'],
                ToPort=rule.ports['ToPort'],
                CidrIp=rule.cidr
            )
        except ClientError as ce:
            print ce.message
        except Exception as e:
            print e.message

    def do_del(self, arg):
        parsed = parse(arg)
        item = parsed[0]
        to_pass = None
        if len(parsed) > 1:
            to_pass = parsed[1:]
        try:
            getattr(self, "del_" + item)(to_pass)
        except Exception as e:
            print "*** {} - Unknown item ***\n{}".format(item, e)

    def del_rule(self, arg):
        # Need to do some validation
        group = arg[0]
        rule = IPRule(arg[1], arg[3], arg[2])
        # cidr = arg[1]
        # protocol = arg[2]
        # ports = [arg[3]]
        # if arg[3] != "-1":
        #     ports = arg[3].split('-')
        # from_port = ports[0]
        # to_port = ports[1] if len(ports) > 1 else ports[0]
        sg = self.aws_session.resource('ec2').SecurityGroup(group)
        try:
            sg.revoke_ingress(
                IpProtocol=rule.protocol,
                FromPort=rule.ports['FromPort'],
                ToPort=rule.ports['ToPort'],
                CidrIp=rule.cidr
            )
        except ClientError as ce:
            print ce.message
        except Exception as e:
            print e.message


def parse(arg):
    return tuple(arg.split())
