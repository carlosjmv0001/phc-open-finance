import pytest
import docker
import time
import os
from src.config import ISSUER_URL, HOLDER_A_URL, HOLDER_B_URL, VERIFIER_A_URL




TEST_ENROLLMENT_KEY = "test-enrollment-secret-key-for-phc-unit-tests-minimum-32-bytes"
TEST_HOLDER_KEY = "test-holder-secret-key-for-phc-unit-tests-minimum-32-bytes-long"


@pytest.fixture(scope="session", autouse=True)
def phc_test_environment():

    os.environ["PHC_ENROLLMENT_SECRET_KEY"] = TEST_ENROLLMENT_KEY
    os.environ["PHC_HOLDER_SECRET_KEY"] = TEST_HOLDER_KEY
    os.environ["PHC_ALLOW_SIMULATED"] = "true"
    os.environ["PHC_DEDUP_BACKEND"] = "json"
    yield
    # Cleanup
    for var in ["PHC_ENROLLMENT_SECRET_KEY", "PHC_HOLDER_SECRET_KEY",
                "PHC_ALLOW_SIMULATED", "PHC_DEDUP_BACKEND"]:
        os.environ.pop(var, None)


@pytest.fixture(scope="session")
def docker_compose():
    if os.getenv("CODESPACES"):
        yield
        return

    try:
        client = docker.from_env()

        containers = ["agent-issuer", "agent-holder-a", "agent-holder-b", "agent-verifier-a", "agent-verifier-b", "tails-server"]

        for container in containers:
            try:
                c = client.containers.get(container)
                if c.status != "running":
                    raise Exception(f"Container {container} is not running")
            except docker.errors.NotFound:
                raise Exception(f"Container {container} not found")

        time.sleep(5)
        yield

    except docker.errors.DockerException:
        yield
    except Exception as e:
        print(f"Warning: {e}")
        yield


@pytest.fixture
def mock_state_file(tmp_path):
    state_file = tmp_path / "test_state.json"
    import src.utils
    original_state_file = src.utils.STATE_FILE
    src.utils.STATE_FILE = str(state_file)
    yield str(state_file)
    src.utils.STATE_FILE = original_state_file


@pytest.fixture
def mock_holder_state_file(tmp_path):
    holder_state_file = tmp_path / "test_holder_state.json"
    import src.utils
    original = src.utils.HOLDER_STATE_FILE
    src.utils.HOLDER_STATE_FILE = str(holder_state_file)
    yield str(holder_state_file)
    src.utils.HOLDER_STATE_FILE = original


@pytest.fixture
def simulated_biometric_provider():
    from src.biometric import SimulatedBiometricProvider
    return SimulatedBiometricProvider(allow_simulated=True)


@pytest.fixture
def simulated_document_verifier():
    from src.biometric import SimulatedDocumentVerifier
    return SimulatedDocumentVerifier(allow_simulated=True)
