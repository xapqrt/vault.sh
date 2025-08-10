from click.testing import CliRunner
from src.cli.commands import cli

def test_cli_init_and_info(monkeypatch, tmp_path):
    monkeypatch.setenv('VAULT_PATH', str(tmp_path / 'vault.dat'))
    r = CliRunner().invoke(cli, ['init','--force'], input='pw\npw\n')
    assert r.exit_code == 0
    assert 'Vault created' in r.output
    r2 = CliRunner().invoke(cli, ['info'], input='pw\n')
    assert r2.exit_code == 0
    assert '"version"' in r2.output

def test_cli_add_and_list(monkeypatch, tmp_path):
    monkeypatch.setenv('VAULT_PATH', str(tmp_path / 'vault.dat'))
    runner = CliRunner()
    runner.invoke(cli, ['init'], input='pw\npw\n')
    add = runner.invoke(cli, ['add-note'], input='pw\nTitle\nContent body\n')
    assert add.exit_code == 0
    assert 'Added note' in add.output
    lst = runner.invoke(cli, ['list'], input='pw\n')
    assert lst.exit_code == 0
    assert 'Title' in lst.output
