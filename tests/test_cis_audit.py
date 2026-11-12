import unittest

import cis_hardening


SWITCH_OK = """no ip source-route
no ip bootp server
no ip http server
no ip http secure-server
username admin privilege 15 secret REDACTED
enable secret REDACTED
 transport input none
 exec-timeout 5 0
 spanning-tree bpduguard enable
 spanning-tree portfast edge
 spanning-tree portfast edge
interface GigabitEthernet0/2
 shutdown
interface GigabitEthernet1/3
 shutdown
"""
FORTI_OK = """set admintimeout 5
set admin-https-ssl-versions tlsv1-2
set admin-lockout-threshold 3
set admin-lockout-duration 60
set trusthost1 192.168.45.0 255.255.255.0
set allowaccess ping https ssh
"""
ROUTER_OK = """permitrootlogin no
permitemptypasswords no
x11forwarding no
maxauthtries 4
logingracetime 30
"""


class AuditTests(unittest.TestCase):
    def test_expected_values_pass(self):
        results = cis_hardening.audit(SWITCH_OK, FORTI_OK, ROUTER_OK)
        self.assertTrue(results)
        self.assertTrue(all(item["status"] == "PASS" for item in results))

    def test_bad_router_value_fails(self):
        results = cis_hardening.audit(SWITCH_OK, FORTI_OK,
                                      ROUTER_OK.replace("x11forwarding no", "x11forwarding yes"))
        self.assertTrue(any(item["status"] == "FAIL" and "X11" in item["control"]
                            for item in results))

    def test_http_admin_access_fails(self):
        results = cis_hardening.audit(SWITCH_OK,
                                      FORTI_OK.replace("ping https ssh", "ping http https ssh"),
                                      ROUTER_OK)
        self.assertTrue(any(item["status"] == "FAIL" and "HTTP/Telnet" in item["control"]
                            for item in results))


if __name__ == "__main__":
    unittest.main()
