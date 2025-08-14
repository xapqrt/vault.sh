from click.testing import CliRunner
from src.cli.commands import cli

def test_cli_help():
	r = CliRunner().invoke(cli, ['--help'])
	assert r.exit_code == 0
	assert 'init' in r.output


def test_decoy_and_real_unlock(monkeypatch, tmp_path):
	# Isolate vault paths
	monkeypatch.setenv('VAULT_PATH', str(tmp_path / 'vault.dat'))
	runner = CliRunner()
	# Init real and decoy with different passwords
	res_real = runner.invoke(cli, ['init','--force'], input='realpw\nrealpw\n')
	assert res_real.exit_code == 0
	res_decoy = runner.invoke(cli, ['init-decoy'], input='fakepw\nfakepw\n')
	assert res_decoy.exit_code == 0
	# Add an entry to real
	add_real = runner.invoke(cli, ['add-note'], input='realpw\nR1\nSecret\n')
	assert add_real.exit_code == 0
	# Listing with decoy password should not show real content
	lst_decoy = runner.invoke(cli, ['list'], input='fakepw\n')
	assert lst_decoy.exit_code == 0
	assert 'R1' not in lst_decoy.output
	# Listing with real password should show
	lst_real = runner.invoke(cli, ['list'], input='realpw\n')
	assert 'R1' in lst_real.output


def test_read_once_note_lifecycle(monkeypatch, tmp_path):
	monkeypatch.setenv('VAULT_PATH', str(tmp_path / 'vault.dat'))
	runner = CliRunner()
	runner.invoke(cli, ['init'], input='pw\npw\n')
	# Create read-once
	cr = runner.invoke(cli, ['note','create','--read-once'], input='pw\nTitle\nBody\n')
	assert cr.exit_code == 0
	# Find id from list
	lst = runner.invoke(cli, ['list'], input='pw\n')
	assert '(read-once)' in lst.output
	# Read should burn
	read = runner.invoke(cli, ['note','read','1'], input='pw\n')
	assert read.exit_code == 0
	assert 'Burned' in read.output
	# Second read should not find
	read2 = runner.invoke(cli, ['note','read','1'], input='pw\n')
	assert 'Not found' in read2.output

