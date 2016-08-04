#AWS Security Group CLI

##Configuration
    AWSShell().cmdloop() #This will use your aws-cli config
    AWSShell(
        aws_access_key_id="KEY",
        aws_secret_access_key="SECRET",
        region_name="us-east-1"
    ).cmdloop()

##Show
    (us-east-1) help show
    show groups                             Shows all security groups in the current region.
    show rules <group-id>           Shows all inbound rules in the specified group.

##Add
    (us-east-1) help add
    add rule <group-id> <cidr> <protocol> <port-range>              Adds an inbound rule to the specified group.
    Example: add rule sg-1234567 192.168.1.42/32 6 80
    Example: add rule sg-1234567 192.168.1.42/32 tcp all
    Example: add rule sg-1234567 192.168.1.42/32 icmp all
    Example: add rule sg-1234567 0.0.0.0/0 all all

##Remove
    (us-east-1) help del
    del rule <group-id> <cidr> <protocol> <port-range>              Removes an inbound rule from the specified group.
    Example: del rule sg-1234567 192.168.1.42/32 6 80
    Example: del rule sg-1234567 192.168.1.42/32 tcp all
    Example: del rule sg-1234567 192.168.1.42/32 icmp all
    Example: del rule sg-1234567 0.0.0.0/0 all all

##Set
    (us-east-1) help set
    set region <region>             Sets the current region. Must be an AWS region name
    (us-east-1)

##TODO
- Implement RDS security groups
- Cleanup dispatch code
- Investigate cmd alternatives