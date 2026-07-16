#!/usr/bin/env python3

import unittest

from select_ios_simulator import SimulatorSelectionError, select_simulator


class SelectIosSimulatorTests(unittest.TestCase):
    def test_selects_newest_runtime_numerically(self) -> None:
        document = {
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-26-9": [
                    {
                        "name": "iPhone 17",
                        "udid": "IOS-26-9",
                        "isAvailable": True,
                    }
                ],
                "com.apple.CoreSimulator.SimRuntime.iOS-26-10": [
                    {
                        "name": "iPhone 17 Pro",
                        "udid": "IOS-26-10",
                        "isAvailable": True,
                    }
                ],
            }
        }

        self.assertEqual(select_simulator(document), "IOS-26-10")

    def test_ignores_non_ios_and_unavailable_devices(self) -> None:
        document = {
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.tvOS-27-0": [
                    {
                        "name": "iPhone-shaped fixture",
                        "udid": "TVOS",
                        "isAvailable": True,
                    }
                ],
                "com.apple.CoreSimulator.SimRuntime.iOS-27-0": [
                    {
                        "name": "iPhone 18",
                        "udid": "UNAVAILABLE",
                        "isAvailable": False,
                    }
                ],
                "com.apple.CoreSimulator.SimRuntime.iOS-26-5": [
                    {
                        "name": "iPhone 17",
                        "udid": "AVAILABLE",
                        "isAvailable": True,
                    }
                ],
            }
        }

        self.assertEqual(select_simulator(document), "AVAILABLE")

    def test_selects_exact_runtime_instead_of_newer_beta(self) -> None:
        document = {
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-27-0": [
                    {
                        "name": "iPhone 18 Pro",
                        "udid": "BETA-27",
                        "isAvailable": True,
                    }
                ],
                "com.apple.CoreSimulator.SimRuntime.iOS-26-5": [
                    {
                        "name": "iPhone 17 Pro",
                        "udid": "STABLE-26-5",
                        "isAvailable": True,
                    }
                ],
            }
        }

        self.assertEqual(
            select_simulator(document, exact_runtime="26.5"),
            "STABLE-26-5",
        )

    def test_rejects_when_exact_runtime_is_unavailable(self) -> None:
        document = {
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-27-0": [
                    {
                        "name": "iPhone 18",
                        "udid": "BETA-ONLY",
                        "isAvailable": True,
                    }
                ]
            }
        }

        with self.assertRaisesRegex(
            SimulatorSelectionError, "for iOS 26.5"
        ):
            select_simulator(document, exact_runtime="26.5")

    def test_rejects_malformed_exact_runtime(self) -> None:
        with self.assertRaisesRegex(
            SimulatorSelectionError, "numeric dotted notation"
        ):
            select_simulator({"devices": {}}, exact_runtime="iOS-26-5")

    def test_tie_breaks_deterministically_by_name(self) -> None:
        document = {
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-26-5": [
                    {
                        "name": "iPhone Pro",
                        "udid": "SECOND",
                        "isAvailable": True,
                    },
                    {
                        "name": "iPhone Base",
                        "udid": "FIRST",
                        "isAvailable": True,
                    },
                ]
            }
        }

        self.assertEqual(select_simulator(document), "FIRST")

    def test_rejects_document_without_an_available_iphone(self) -> None:
        with self.assertRaisesRegex(
            SimulatorSelectionError, "no available iPhone simulator"
        ):
            select_simulator({"devices": {}})

    def test_rejects_malformed_document(self) -> None:
        with self.assertRaisesRegex(SimulatorSelectionError, "devices object"):
            select_simulator([])


if __name__ == "__main__":
    unittest.main()
