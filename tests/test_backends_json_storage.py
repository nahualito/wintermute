import os
from tempfile import TemporaryDirectory

from wintermute.backends.json_storage import JsonFileBackend


def test_json_backend_save_and_load() -> None:
    with TemporaryDirectory() as tmp_dir:
        backend = JsonFileBackend(base_path=tmp_dir)
        op_id = "test-op-001"
        data = {"key": "value", "list": [1, 2, 3]}

        # Test Save
        assert backend.save(op_id, data) is True

        # Verify file exists
        expected_path = os.path.join(tmp_dir, f"{op_id}.json")
        assert os.path.exists(expected_path)

        # Test Load
        loaded_data = backend.load(op_id)
        assert loaded_data == data


def test_json_backend_list_all() -> None:
    with TemporaryDirectory() as tmp_dir:
        backend = JsonFileBackend(base_path=tmp_dir)
        backend.save("op1", {"v": 1})
        backend.save("op2", {"v": 2})

        all_ops = backend.list_all()
        assert len(all_ops) == 2
        assert "op1" in all_ops
        assert "op2" in all_ops
