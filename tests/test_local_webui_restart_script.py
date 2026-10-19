"""Exercise the manual restart helper using synthetic files and mocked PowerShell APIs."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Exercises the Windows PowerShell helper')
SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'restart_local_webui.ps1'

HARNESS = r"""
param([string]$Helper, [string]$FixtureFile, [string]$Scenario, [switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility
$fixture = Get-Content -LiteralPath $FixtureFile -Raw | ConvertFrom-Json
$global:restartTestEvents = New-Object System.Collections.Generic.List[object]
$global:restartTestStored = $fixture.config
$global:restartTestListenerId = if ($Scenario -eq 'owned-child') { 4101 } else { 4100 }
if ($Scenario -eq 'wrong-pid') { $global:restartTestListenerId = 4900 }
$global:restartTestEnvironmentBefore = @{}
foreach ($name in @('CHECKIN_WEB_HOST', 'CHECKIN_WEB_PORT', 'CHECKIN_AUTH_ROOT')) {
    $global:restartTestEnvironmentBefore[$name] = [Environment]::GetEnvironmentVariable($name)
}
function Copy-Object($value) { return $value | ConvertTo-Json -Depth 40 -Compress | ConvertFrom-Json }
function Invoke-RestMethod {
    [CmdletBinding()]
    param($Uri, $Method = 'Get', $Headers, $ContentType, $Body, $WebSession, $TimeoutSec)
    $path = ([uri]$Uri).AbsolutePath
    $request = if ($Body) { $Body | ConvertFrom-Json } else { $null }
    $global:restartTestEvents.Add(@{kind = 'http'; path = $path; method = [string]$Method; body = $request})
    switch ($path) {
        '/api/login' { return @{csrf = 'synthetic-csrf'} }
        '/api/status' { return @{running = ($Scenario -eq 'active-task')} }
        '/healthz' { return @{ok = $true} }
        '/api/config' {
            if ([string]$Method -eq 'Put') {
                $global:restartTestStored = Copy-Object $request.config
            }
            return @{config = (Copy-Object $global:restartTestStored); revision = 12}
        }
        default { throw "Unexpected HTTP endpoint: $path" }
    }
}
function Get-NetTCPConnection {
    [CmdletBinding()]
    param($LocalPort, $State)
    $global:restartTestEvents.Add(@{kind = 'listener'; port = $LocalPort; state = $State})
    return @{OwningProcess = $global:restartTestListenerId}
}
function Get-CimInstance {
    [CmdletBinding()]
    param($ClassName, $Filter)
    $global:restartTestEvents.Add(@{kind = 'cim'; filter = $Filter})
    $processId = [int]($Filter -replace '^ProcessId=', '')
    $command = '"' + (Join-Path $fixture.repository '.venv\Scripts\python.exe') + '" -m server'
    if ($Scenario -eq 'wrong-command') { $command = 'unrelated-python.exe -m unrelated-service' }
    return @{
        ProcessId = $processId
        ParentProcessId = if ($Scenario -eq 'owned-child') { 4100 } else { 4000 }
        CommandLine = $command
    }
}
function Stop-Process {
    [CmdletBinding()]
    param($Id)
    $global:restartTestEvents.Add(@{kind = 'stop'; id = $Id})
}
function Wait-Process {
    [CmdletBinding()]
    param($Id, $Timeout)
    $global:restartTestEvents.Add(@{kind = 'wait'; id = $Id; timeout = $Timeout})
}
function Start-Process {
    [CmdletBinding()]
    param($FilePath, $ArgumentList, $WorkingDirectory, $WindowStyle, $RedirectStandardOutput,
        $RedirectStandardError, [switch]$PassThru)
    $global:restartTestEvents.Add(@{
        kind = 'start'; file = $FilePath; arguments = $ArgumentList; directory = $WorkingDirectory
        window = [string]$WindowStyle; stdout = $RedirectStandardOutput; stderr = $RedirectStandardError
    })
    return @{Id = 5200}
}
function Start-Sleep {
    [CmdletBinding()]
    param($Milliseconds)
    $global:restartTestEvents.Add(@{kind = 'sleep'; milliseconds = $Milliseconds})
}
$success = $false
$failure = $null
try {
    $null = & $Helper -TestRoot $fixture.testRoot -RepositoryRoot $fixture.repository `
        -UseSystemChrome -CheckOnly:$CheckOnly
    $success = $true
} catch { $failure = $_.Exception.Message + ' at ' + $_.InvocationInfo.PositionMessage }
$environmentAfter = @{}
foreach ($name in $global:restartTestEnvironmentBefore.Keys) {
    $environmentAfter[$name] = [Environment]::GetEnvironmentVariable($name)
}
@{
    success = $success; error = $failure; events = @($global:restartTestEvents.ToArray()); stored = $global:restartTestStored
    environmentBefore = $global:restartTestEnvironmentBefore; environmentAfter = $environmentAfter
} | ConvertTo-Json -Depth 50 -Compress
"""


@pytest.fixture
def restart_fixture(tmp_path):
	powershell = shutil.which('powershell.exe')
	if not powershell:
		candidate = Path(os.environ.get('SYSTEMROOT', r'C:\Windows')) / (
			'System32/WindowsPowerShell/v1.0/powershell.exe'
		)
		if not candidate.is_file():
			pytest.skip('Windows PowerShell is unavailable')
		powershell = str(candidate)
	repository = tmp_path / 'synthetic repository'
	test_root = tmp_path / 'synthetic test data'
	files = {
		repository / '.venv' / 'Scripts' / 'python.exe': b'not an executable',
		test_root / 'web-password': b'synthetic-admin-password',
		test_root / 'keys' / 'master.key': bytes(range(32)),
		test_root / 'process-id': b'4100',
		test_root / 'data' / 'auth-cache' / 'auth-state.enc': b'synthetic encrypted snapshot',
		test_root / 'data' / 'webui.sqlite3': b'synthetic encrypted database',
	}
	for path, value in files.items():
		path.parent.mkdir(parents=True, exist_ok=True)
		path.write_bytes(value)
	config = {
		'browser': {'engine': 'cloakbrowser'},
		'accounts': [{'id': 'saved-account', 'provider': 'anyrouter', 'api_user': '123'}],
		'identities': {'saved-ld': {'type': 'linuxdo', 'proxy': 'direct'}},
		'providers': {'custom': {'domain': 'https://example.test'}},
		'notifications': {'fy1push': {'token': 'synthetic-notification-token'}},
		'schedule': {'enabled': False, 'time': '09:00'},
	}
	fixture_file = tmp_path / 'fixture.json'
	fixture_file.write_text(
		json.dumps({'repository': str(repository), 'testRoot': str(test_root), 'config': config}), encoding='utf-8'
	)
	harness = tmp_path / 'mocked-restart.ps1'
	harness.write_text(HARNESS, encoding='utf-8')

	def run(scenario='owned', *, check_only=False):
		command = [
			powershell,
			'-NoProfile',
			'-NonInteractive',
			'-ExecutionPolicy',
			'Bypass',
			'-File',
			str(harness),
			'-Helper',
			str(SCRIPT),
			'-FixtureFile',
			str(fixture_file),
			'-Scenario',
			scenario,
		]
		if check_only:
			command.append('-CheckOnly')
		completed = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
		assert completed.returncode == 0, completed.stderr
		return json.loads(completed.stdout.strip())

	return run, files, config, repository, test_root


def _assert_no_task_endpoints(result):
	requests = [event for event in result['events'] if event['kind'] == 'http']
	assert all(event['path'] in {'/api/login', '/api/status', '/api/config', '/healthz'} for event in requests)
	assert all(event['method'].lower() in {'get', 'put'} for event in requests if event['path'] != '/api/login')
	return requests


def test_restart_check_only_preserves_files_config_environment_and_processes(restart_fixture):
	run, files, config, _, _ = restart_fixture
	result = run(check_only=True)
	assert result['success'] is True, result['error']
	assert result['stored'] == config
	assert result['environmentBefore'] == result['environmentAfter']
	assert not any(event['kind'] in {'stop', 'wait', 'start', 'sleep'} for event in result['events'])
	assert all(event['method'].lower() != 'put' for event in _assert_no_task_endpoints(result))
	assert all(path.read_bytes() == value for path, value in files.items())


@pytest.mark.parametrize(
	('scenario', 'error'),
	[
		('active-task', 'A task is running'),
		('wrong-pid', 'does not match the recorded local test process'),
		('wrong-command', 'not the expected repository WebUI'),
	],
)
def test_restart_rejects_unsafe_state_before_any_process_mutation(restart_fixture, scenario, error):
	run, files, config, _, _ = restart_fixture
	result = run(scenario)
	assert result['success'] is False
	assert error in result['error']
	assert result['stored'] == config
	assert not any(event['kind'] in {'stop', 'wait', 'start', 'sleep'} for event in result['events'])
	if scenario == 'active-task':
		assert not any(event['kind'] in {'listener', 'cim'} for event in result['events'])
	assert all(event['method'].lower() != 'put' for event in _assert_no_task_endpoints(result))
	assert all(path.read_bytes() == value for path, value in files.items())


@pytest.mark.parametrize(('scenario', 'listener_id'), [('owned', 4100), ('owned-child', 4101)])
def test_idle_owned_restart_only_stops_listener_and_preserves_settings_and_snapshot(
	restart_fixture, scenario, listener_id
):
	run, files, config, repository, test_root = restart_fixture
	result = run(scenario)
	assert result['success'] is True, result['error']
	events = result['events']
	assert [event['id'] for event in events if event['kind'] == 'stop'] == [listener_id]
	assert [event['id'] for event in events if event['kind'] == 'wait'] == [listener_id]
	starts = [event for event in events if event['kind'] == 'start']
	assert len(starts) == 1
	assert starts[0]['window'] == 'Hidden'
	assert starts[0]['file'] == str(repository / '.venv' / 'Scripts' / 'python.exe')
	assert starts[0]['arguments'] == ['-m', 'server']
	assert starts[0]['directory'] == str(repository)
	assert starts[0]['stdout'] == str(test_root / 'stdout.log')
	assert starts[0]['stderr'] == str(test_root / 'stderr.log')
	assert [event['kind'] for event in events].index('stop') < [event['kind'] for event in events].index('start')
	requests = _assert_no_task_endpoints(result)
	puts = [event for event in requests if event['method'].lower() == 'put']
	assert len(puts) == 1
	assert puts[0]['path'] == '/api/config'
	assert puts[0]['body']['revision'] == 12
	expected = {**config, 'browser': {'engine': 'chrome'}}
	assert puts[0]['body']['config'] == expected
	assert result['stored'] == expected
	assert (test_root / 'process-id').read_text().strip() == '5200'
	assert all(path.read_bytes() == value for path, value in files.items() if path.name != 'process-id')
