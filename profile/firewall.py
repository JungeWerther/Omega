"""Per-user firewall for the agent (iptables owner match).

Landlock's network rules (profile/policy.py) restrict destination *ports*
only, so on its own the agent could still reach an attacker's server on
port 8080, 8090 or 3128. These rules restrict the destination *address*:
packets from the agent's uid may only go to 127.0.0.1 on the ports listed
in the policy (`network_policy.connect_tcp`), plus any `egressExtraPorts`.
Everything else is refused, UDP included, so the agent cannot use DNS
either; the egress proxy resolves names for it.

Run as root by entrypoint.sh, before the agent starts:

    python3 -I profile/firewall.py --policy profile/policy.yaml --uid 65534 [--extra-ports 9765]

It needs CAP_NET_ADMIN (the launcher adds it). The rules live in a chain
of their own, OMEGA_AGENT, and are re-created on every start.
"""

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass

import yaml

CHAIN = "OMEGA_AGENT"


@dataclass(frozen=True)
class AgentFirewall:
    uid: int
    loopback_ports: tuple
    extra_ports: tuple = ()

    def ipv4_rules(self):
        rules = [["-o", "lo", "-d", "127.0.0.1/32", "-p", "tcp", "-m", "multiport",
                  "--dports", ",".join(map(str, self.loopback_ports)), "-j", "RETURN"]]
        if self.extra_ports:
            rules.append(["-p", "tcp", "-m", "multiport",
                          "--dports", ",".join(map(str, self.extra_ports)), "-j", "RETURN"])
        return rules + self._refuse_rest("icmp-admin-prohibited")

    def ipv6_rules(self):
        return self._refuse_rest("icmp6-adm-prohibited")

    @staticmethod
    def _refuse_rest(prohibited):
        # TCP is rejected as "administratively prohibited": connect() fails
        # at once with EHOSTUNREACH, which the agent's self-test can tell
        # apart from a closed port (ECONNREFUSED). Everything else is
        # dropped, which locally generated packets see as EPERM.
        return [["-p", "tcp", "-j", "REJECT", "--reject-with", prohibited], ["-j", "DROP"]]

    def commands(self, tool, rules):
        jump = ["-m", "owner", "--uid-owner", str(self.uid), "-j", CHAIN]
        return [
            # Remove a previous installation (ignore failures: first start).
            ([tool, "-D", "OUTPUT", *jump], False),
            ([tool, "-F", CHAIN], False),
            ([tool, "-X", CHAIN], False),
            ([tool, "-N", CHAIN], True),
            *(([tool, "-A", CHAIN, *rule], True) for rule in rules),
            ([tool, "-I", "OUTPUT", "1", *jump], True),
            ([tool, "-C", "OUTPUT", *jump], True),
        ]

    def plan(self, ipv6=True):
        steps = self.commands("iptables", self.ipv4_rules())
        if ipv6:
            steps += self.commands("ip6tables", self.ipv6_rules())
        return steps


def load(policy_path, uid, extra_ports=()):
    with open(policy_path) as source:
        policy = yaml.safe_load(source) or {}
    ports = (policy.get("network_policy") or {}).get("connect_tcp")
    if not ports:
        raise SystemExit(f"firewall: {policy_path} has no network_policy.connect_tcp")
    return AgentFirewall(uid=uid,
                         loopback_ports=tuple(sorted({int(p) for p in ports})),
                         extra_ports=tuple(sorted({int(p) for p in extra_ports})))


def ipv6_enabled():
    return os.path.exists("/proc/net/if_inet6")


def apply(firewall, run=subprocess.run):
    for command, required in firewall.plan(ipv6=ipv6_enabled()):
        result = run(command, capture_output=True, text=True)
        if required and result.returncode != 0:
            raise SystemExit(f"firewall: `{' '.join(command)}` failed: {result.stderr.strip()}")


def parse_ports(text):
    return [int(p) for p in str(text or "").split(",") if p.strip()]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--policy", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--extra-ports", default="")
    args = parser.parse_args(argv)
    firewall = load(args.policy, args.uid, parse_ports(args.extra_ports))
    apply(firewall)
    print(f"firewall: uid {firewall.uid} may connect to 127.0.0.1 on {list(firewall.loopback_ports)}"
          + (f" and any host on {list(firewall.extra_ports)}" if firewall.extra_ports else "")
          + "; all other traffic, UDP included, is refused")


if __name__ == "__main__":
    main(sys.argv[1:])
