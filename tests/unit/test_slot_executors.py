"""Комплексные тесты для всех 16 слотов функциональной матрицы Epitaph."""
from __future__ import annotations

import unittest
from epitaph.execution.checkers.telegram import TelegramExecutor, TelegramProfileMetadata
from epitaph.execution.checkers.phone import PhoneExecutor, PhoneMetadata
from epitaph.execution.checkers.fullname import FullNameExecutor, PersonMetadata
from epitaph.execution.checkers.inn import InnExecutor, InnMetadata
from epitaph.execution.checkers.snils import SnilsExecutor, SnilsMetadata
from epitaph.execution.checkers.vehicle import VehicleExecutor, VehicleMetadata
from epitaph.execution.checkers.organization import OrganizationExecutor, OrganizationMetadata
from epitaph.execution.checkers.bank_card import BankCardExecutor, BankCardMetadata
from epitaph.execution.checkers.password import PasswordExecutor, PasswordBreachMetadata
from epitaph.execution.checkers.cookies import CookieExecutor, CookieAuditMetadata
from epitaph.execution.checkers.ip import IpExecutor, IpMetadata
from epitaph.execution.checkers.subdomain import SubdomainExecutor, SubdomainMetadata
from epitaph.execution.checkers.port_scanner import PortScannerExecutor, PortScanMetadata
from epitaph.execution.checkers.mac import MacExecutor, MacMetadata


class TestAllSlots(unittest.TestCase):
    def test_telegram_clean(self):
        ex = TelegramExecutor()
        self.assertEqual(ex._clean_target("@durov"), "durov")
        self.assertEqual(ex._clean_target("https://t.me/telegram"), "telegram")

    def test_phone_sanitization(self):
        ex = PhoneExecutor()
        self.assertEqual(ex._sanitize("+380 (50) 123-45-67"), "+380501234567")
        country, code, _ = ex._detect_country("+380501234567")
        self.assertEqual(country, "Украина")
        self.assertEqual(code, "+380")

    def test_fullname_parsing(self):
        ex = FullNameExecutor()
        meta = ex._parse_fio("иванов иван иванович")
        self.assertIsNotNone(meta)
        self.assertEqual(meta.last_name, "Иванов")
        self.assertEqual(meta.first_name, "Иван")
        self.assertEqual(meta.middle_name, "Иванович")
        self.assertEqual(meta.gender_estimate, "MALE")

    def test_inn_validation(self):
        ex = InnExecutor()
        res_legal = ex._validate_inn("7707083893")
        self.assertTrue(res_legal.is_valid)
        self.assertEqual(res_legal.region_code, "77")
        res_invalid = ex._validate_inn("1234567890")
        self.assertFalse(res_invalid.is_valid)

    def test_snils_validation(self):
        ex = SnilsExecutor()
        res = ex._validate_snils("112-233-445 95")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.formatted_snils, "112-233-445 95")
        res_bad = ex._validate_snils("000-000-000 00")
        self.assertFalse(res_bad.is_valid)

    def test_vehicle_parsing(self):
        ex = VehicleExecutor()
        ua = ex._parse_vehicle("AE1234BC")
        self.assertTrue(ua.is_valid)
        self.assertEqual(ua.region_code, "AE")
        vin = ex._parse_vehicle("WAUZZZ8K9BA123456")
        self.assertTrue(vin.is_valid)
        self.assertEqual(vin.country, "Международный (VIN)")

    def test_organization_ogrn(self):
        ex = OrganizationExecutor()
        ogrn_res = ex._validate_ogrn("1027700132195")
        self.assertTrue(ogrn_res.is_valid_ogrn)

    def test_bank_card_luhn(self):
        ex = BankCardExecutor()
        self.assertTrue(ex._check_luhn("4532015112830366"))
        self.assertFalse(ex._check_luhn("4532015112830367"))
        meta = ex._analyze_card("4532015112830366")
        self.assertEqual(meta.payment_system, "Visa")
        self.assertTrue(meta.is_luhn_valid)

    def test_password_entropy(self):
        ex = PasswordExecutor()
        ent = ex._calculate_entropy("Password123!")
        self.assertGreater(ent, 50.0)

    def test_cookie_audit(self):
        ex = CookieExecutor()
        raw = "example.com\tTRUE\t/\tTRUE\t1735689600\tsession_id\tabc123\n"
        meta = ex._audit_cookies(raw)
        self.assertEqual(meta.total_parsed, 1)
        self.assertEqual(meta.secure_count, 1)

    def test_ip_bogon(self):
        import ipaddress
        ip1 = ipaddress.ip_address("192.168.1.1")
        self.assertTrue(ip1.is_private)
        ip2 = ipaddress.ip_address("8.8.8.8")
        self.assertFalse(ip2.is_private)

    def test_subdomain_clean(self):
        ex = SubdomainExecutor()
        self.assertEqual(ex._clean_domain("https://api.example.com/v1"), "api.example.com")

    def test_mac_normalization(self):
        ex = MacExecutor()
        parsed = ex._normalize("00:1a:2b:3c:4d:5e")
        self.assertIsNotNone(parsed)
        norm, oui, is_multi, is_local = parsed
        self.assertEqual(norm, "00:1A:2B:3C:4D:5E")
        self.assertEqual(oui, "00:1A:2B")
        self.assertFalse(is_multi)


if __name__ == "__main__":
    unittest.main()
