import pytest
from unittest.mock import patch, Mock
from src.collusion_guard import (
    validate_architectural_separation,
    verify_no_issuer_tracking,
    validate_proof_request_compliance,
    SeparationProof,
)


@pytest.mark.phc
class TestArchitecturalSeparation:
    def test_same_endpoint_fails(self):
        assert not validate_architectural_separation(
            "http://localhost:8001", "http://localhost:8001"
        )

    def test_different_endpoints_pass(self):
        with patch("src.collusion_guard.requests.get") as mock_get:
            mock_get.side_effect = [
                Mock(json=Mock(return_value={"result": {"did": "did:sov:issuer1"}})),
                Mock(json=Mock(return_value={"result": {"did": "did:sov:verifier1"}})),
                Mock(json=Mock(return_value={"results": [{"verkey": "key_issuer_1"}]})),
                Mock(json=Mock(return_value={"results": [{"verkey": "key_verifier_1"}]})),
                Mock(status_code=404),
                Mock(status_code=200, json=Mock(return_value={"result": {"verkey": "key_issuer_1"}})),
                Mock(status_code=404),
                Mock(status_code=200, json=Mock(return_value={"result": {"verkey": "key_verifier_1"}})),
            ]
            assert validate_architectural_separation(
                "http://localhost:8001", "http://localhost:8021"
            )

    def test_same_did_fails(self):
        with patch("src.collusion_guard.requests.get") as mock_get:
            mock_get.side_effect = [
                Mock(json=Mock(return_value={"result": {"did": "did:sov:same"}})),
                Mock(json=Mock(return_value={"result": {"did": "did:sov:same"}})),
            ]
            assert not validate_architectural_separation(
                "http://localhost:8001", "http://localhost:8021"
            )

    def test_network_error_still_passes(self):
        with patch("src.collusion_guard.requests.get", side_effect=Exception("Network")):
            assert validate_architectural_separation(
                "http://localhost:8001", "http://localhost:8021"
            )


@pytest.mark.phc
class TestSeparationProof:
    def test_to_dict(self):
        proof = SeparationProof(
            issuer_did="did:sov:issuer1",
            verifier_did="did:sov:verifier1",
            challenge="abc123",
            issuer_signature="sig1",
            verifier_signature="sig2",
            issuer_endpoint="http://localhost:8001",
            verifier_endpoint="http://localhost:8021",
            keys_are_different=True,
            timestamp=1711900800,
            verified=True,
        )
        d = proof.to_dict()
        assert d["issuer_did"] == "did:sov:issuer1"
        assert d["verified"] is True
        assert d["keys_are_different"] is True


@pytest.mark.phc
class TestNoIssuerTracking:
    def test_no_revealed_attrs_passes(self):
        proof_record = {
            "by_format": {
                "pres": {
                    "anoncreds": {
                        "requested_proof": {
                            "revealed_attrs": {},
                            "revealed_attr_groups": {},
                        }
                    }
                }
            }
        }
        assert verify_no_issuer_tracking(proof_record)

    def test_person_hash_leaked_fails(self):
        proof_record = {
            "by_format": {
                "pres": {
                    "anoncreds": {
                        "requested_proof": {
                            "revealed_attrs": {},
                            "revealed_attr_groups": {
                                "group1": {
                                    "values": {
                                        "person_hash": {"raw": "abc123", "encoded": "123"},
                                        "biometric_score": {"raw": "95", "encoded": "95"},
                                    }
                                }
                            },
                        }
                    }
                }
            }
        }
        assert not verify_no_issuer_tracking(proof_record)

    def test_controller_did_leaked_fails(self):
        proof_record = {
            "by_format": {
                "pres": {
                    "anoncreds": {
                        "requested_proof": {
                            "revealed_attrs": {},
                            "revealed_attr_groups": {
                                "group1": {
                                    "values": {
                                        "controller_did": {"raw": "did:sov:x", "encoded": "1"},
                                    }
                                }
                            },
                        }
                    }
                }
            }
        }
        assert not verify_no_issuer_tracking(proof_record)

    def test_only_safe_attrs_passes(self):
        proof_record = {
            "by_format": {
                "pres": {
                    "anoncreds": {
                        "requested_proof": {
                            "revealed_attrs": {},
                            "revealed_attr_groups": {
                                "group1": {
                                    "values": {
                                        "timestamp": {"raw": "1711900800", "encoded": "1711900800"},
                                    }
                                }
                            },
                        }
                    }
                }
            }
        }
        assert verify_no_issuer_tracking(proof_record)

    def test_empty_proof_passes(self):
        assert verify_no_issuer_tracking({})

    def test_verifier_requesting_dangerous_attr_fails(self):
        proof_record = {
            "by_format": {
                "pres": {
                    "anoncreds": {
                        "requested_proof": {
                            "revealed_attrs": {},
                            "revealed_attr_groups": {},
                        }
                    }
                },
                "pres_request": {
                    "anoncreds": {
                        "requested_attributes": {
                            "0_person_hash": {"name": "person_hash"}
                        }
                    }
                }
            }
        }
        assert not verify_no_issuer_tracking(proof_record)


@pytest.mark.phc
class TestProofRequestCompliance:
    def test_empty_attributes_passes(self):
        proof_request = {
            "presentation_request": {
                "anoncreds": {
                    "requested_attributes": {},
                    "requested_predicates": {"0_bio": {"name": "biometric_score", "p_type": ">=", "p_value": 80}},
                }
            }
        }
        assert validate_proof_request_compliance(proof_request)

    def test_person_hash_requested_blocked(self):
        proof_request = {
            "presentation_request": {
                "anoncreds": {
                    "requested_attributes": {
                        "0_ph": {"name": "person_hash"}
                    },
                }
            }
        }
        assert not validate_proof_request_compliance(proof_request)

    def test_controller_did_requested_blocked(self):
        proof_request = {
            "presentation_request": {
                "anoncreds": {
                    "requested_attributes": {
                        "0_cd": {"name": "controller_did"}
                    },
                }
            }
        }
        assert not validate_proof_request_compliance(proof_request)
