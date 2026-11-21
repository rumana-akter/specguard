import pytest

from specguard.compiler import compile_spec, compile_static, unrestricted
from specguard.inventory import load_inventory
from specguard.paths import default_eval_dir, default_repo
from specguard.spec import load_spec


@pytest.fixture(scope="session")
def inv():
    return load_inventory(default_repo())


@pytest.fixture(scope="session")
def eval_dir():
    return default_eval_dir()


@pytest.fixture
def spec_policy(inv):
    def make(task_id):
        return compile_spec(load_spec(inv.root / "specs" / f"{task_id}.toml"), inv).policy
    return make


@pytest.fixture
def static_policy(inv):
    return lambda role, task="T-1": compile_static(role, inv, task).policy


@pytest.fixture
def open_policy(inv):
    return unrestricted(inv, "T-1").policy
