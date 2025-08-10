from click.testing import CliRunner
from src.cli.commands import cli

def test_cli_help():
	r = CliRunner().invoke(cli, ['--help'])
	assert r.exit_code == 0
	assert 'init' in r.output

