#AWS Security Group CLI

    (us-east-1) help add
    add rule <group-id> <cidr> <protocol> <port-range>              Adds an inbound rule to the specified group.
    Example: add rule sg-1234567 192.168.1.42/32 6 80
    Example: add rule sg-1234567 192.168.1.42/32 tcp all
    Example: add rule sg-1234567 192.168.1.42/32 icmp all
    Example: add rule sg-1234567 0.0.0.0/0 all all
