# Network and Firewall Research Findings

## Alpine networking

Source: https://wiki.alpinelinux.org/wiki/Configure_Networking

Alpine Linux uses ifupdown-ng for network configuration by default, while NetworkManager and wireless tools are also supported. The standard persistent interface file is `/etc/network/interfaces`. Alpine's setup scripts can configure Ethernet, wireless, bridge, bond, and VLAN interfaces. The `networking` OpenRC service can be restarted with `rc-service networking restart` and enabled at boot with `rc-update add networking boot`.

The same page recommends `ip link` or `ip a` to list interfaces and shows that `setup-interfaces` can configure interfaces. The agent should prefer read-only `ip` inspection and treat changes to `/etc/network/interfaces` as high impact because an incorrect change can remove connectivity.

## Alpine iptables

Source: https://wiki.alpinelinux.org/wiki/Iptables

Alpine's iptables package includes `ip6tables` on Alpine 3.19 and newer. The persistent OpenRC workflow is to install `iptables`, add the `iptables` service to the runlevel with `rc-update add iptables`, and save rules with `rc-service iptables save`. The equivalent applies to `ip6tables` on systems where it is separate. Alpine Local Backup (`lbu`) may also be needed on diskless systems.

The agent should support inspecting current rules, saving current rules to a private backup, and invoking the OpenRC save/reload operations only after explicit confirmation. It must keep IPv4 and IPv6 rules distinct.

## iptables-save

Source: https://man7.org/linux/man-pages/man8/iptables-save.8.html

`iptables-save` dumps the current IPv4 ruleset in a parseable format and can write to a specified file with `-f`. The corresponding `ip6tables-save` handles IPv6. The agent should use these commands for backups rather than parsing human-formatted `iptables -L` output.

## Safety design

Network-interface modifications require an exact interface name and an explicit operation. The agent must refuse unsafe interface names and must not automatically change the active management interface unless the operator has explicitly confirmed it. It should not add a default route, replace DNS, or change Wi-Fi credentials implicitly.

Firewall changes must be previewed before execution. The agent should create a timestamped backup of IPv4 and IPv6 rules before applying a new rules file, validate files with `iptables-restore --test` or `ip6tables-restore --test` when available, and provide a rollback command. It must warn that a default DROP policy can disconnect remote administration and should not be applied automatically over SSH.

The agent should never flush all rules as an implicit step. A complete restore or flush is a separate high-risk action with explicit confirmation. The default mode remains read-only.
