import pytest
from pathlib import Path
from src.lib.utils import VaultStorage, StorageError, EntryManager, EntryError

def make_storage(tmp_path: Path):
    return VaultStorage(tmp_path / 'vault.dat')

def test_vault_init_and_load(tmp_path: Path):
    vs = make_storage(tmp_path)
    assert not vs.exists()
    vs.init('master')
    assert vs.exists()
    data = vs.load('master')
    assert data['metadata']['version'] == '1.0'

def test_vault_init_twice(tmp_path: Path):
    vs = make_storage(tmp_path)
    vs.init('pw')
    with pytest.raises(StorageError):
        vs.init('pw')

def test_vault_load_wrong_password(tmp_path: Path):
    vs = make_storage(tmp_path)
    vs.init('pw1')
    with pytest.raises(StorageError):
        vs.load('pw2')

def test_vault_save_and_reload(tmp_path: Path):
    vs = make_storage(tmp_path)
    vs.init('pw')
    data = vs.load('pw')
    data['data']['entries']['x'] = {'dummy': True}
    vs.save('pw', data)
    re = vs.load('pw')
    assert 'x' in re['data']['entries']

def test_entry_manager_basic(tmp_path: Path):
    vs = make_storage(tmp_path); vs.init('pw'); data = vs.load('pw')
    logical = {'entries': data['data']['entries'], 'metadata': {}}
    em = EntryManager()
    eid = em.create_entry(logical, 'Title', 'note', 'Body', ['tag'])
    assert eid == '1'
    assert em.get_entry(logical, eid).title == 'Title'
    assert len(em.list_entries(logical)) == 1
    data['data']['entries'] = logical['entries']
    vs.save('pw', data)

def test_entry_manager_large_content(tmp_path: Path):
    vs = make_storage(tmp_path); vs.init('pw')
    data = {'entries': {}, 'metadata': {}}
    em = EntryManager()
    with pytest.raises(EntryError):
        em.create_entry(data, 'Big', 'note', 'A' * (2 * 1024 * 1024))
