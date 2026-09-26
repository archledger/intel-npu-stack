#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Invariants of the release workflow: jobs, runners, permissions, secrets, environments, action pins and inputs,
handoffs, gate calls and their arguments, the commands of each run block and their quoting, the shell, conditions,
step keys and working directories, and the two installer legs."""
import argparse
import contextlib
import importlib
import io
import itertools
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

import release_publish as publish

try:
    import yaml
except ImportError:  # the Fedora tools install python3-pyyaml; elsewhere the invariants are skipped
    yaml = None

REPO = Path(__file__).resolve().parents[2]
JOBS = {
    'preflight': {'contents': 'read', 'pages': 'read'},
    'sign': {'contents': 'read'},
    'installer-a': {'contents': 'read'},
    'installer-b': {'contents': 'read'},
    'verify': {'contents': 'read'},
    'finalize': {'contents': 'read'},
    'attest': {'contents': 'read', 'id-token': 'write', 'attestations': 'write'},
    'publish-release': {'contents': 'write'},
    'pages-build': {'contents': 'read'},
    'pages-deploy': {'contents': 'read', 'pages': 'write', 'id-token': 'write'},
    'verify-live': {'contents': 'read'},
}
KEY_JOBS = {'sign', 'finalize'}
# Every job runs once, on a fresh GitHub-hosted runner, and has only these keys: a strategy could run it as a matrix,
# and a self-hosted runner, which other workflows share, would receive the key or a write token.
RUNNER = 'ubuntu-24.04'
JOB_KEYS = {'name', 'needs', 'runs-on', 'timeout-minutes', 'environment', 'permissions', 'container', 'env', 'outputs',
            'steps'}
KEY_JOB_ACTIONS = ('actions/checkout@', 'actions/download-artifact@', 'actions/upload-artifact@')
# The one step of each key job between Import and Destroy: the only step that runs while the key is present.
SIGNING_STEPS = {'sign': 'Sign and assemble the production release tree',
                 'finalize': 'Sign the installer, install.sh and SHA256SUMS'}
# The tool calls of each signing step, in order: (tool, subcommand or None). CALLS pins the calls of a whole job, not
# the step that makes them, so a gate that needs no key could otherwise move into the signing step and run after
# Import while the job still makes every call in the same order.
SIGNING_CALLS = {'sign': [('release_trust', 'read')] * 3 + [('release_sign', None)],
                 'finalize': [('release_trust', 'read'), ('release_site', 'sign')]}
LEG_PERTURBATIONS = {'LEG', 'LEG_UMASK', 'TZ', 'LANG', 'CARGO_BUILD_JOBS'}
EXPRESSION = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')
ALLOWED = re.compile(r'inputs\.[a-z0-9_]+|secrets\.[A-Z0-9_]+|vars\.[A-Z0-9_]+|github\.token'
                     r'|needs\.[a-z0-9-]+\.outputs\.[a-z0-9_]+|steps\.[a-z0-9-]+\.outputs\.[a-z0-9_]+')
TOOL = re.compile(r'python3\s+(?:src/)?scripts/ci/(\w+)\.py')
TOOL_MENTION = re.compile(r'scripts/ci/\w+\.py')
NESTED = re.compile(r'\$\((python3\s[^()]*)\)')
SUBSTITUTED = re.compile(r'substituted(\d+)')
SHELL_VARIABLE = re.compile(r'\$\{?([A-Z_][A-Z0-9_]*)\}?')
CHECKOUT = ('actions/checkout', {'persist-credentials': False, 'path': 'src'})
TOOLCHAIN = ('dtolnay/rust-toolchain', {'toolchain': '1.85.0'})


def upload(name, path):
    return 'actions/upload-artifact', {'name': name, 'path': path, 'if-no-files-found': 'error', 'retention-days': 7}


def download(name, path):
    return 'actions/download-artifact', {'name': name, 'path': path}


# The actions each job runs, in order, with their inputs. Every checkout takes the run's commit into src and keeps no
# token. A job that holds the key runs only KEY_JOB_ACTIONS. attest covers every file SHA256SUMS lists and the four
# release assets, SHA256SUMS and its signature among them, so every served file and every asset of the release. The
# Pages artifact goes from upload-pages-artifact straight to deploy-pages.
ACTIONS = {
    'preflight': [CHECKOUT, TOOLCHAIN, upload('release-inputs', 'work/release-inputs')],
    'sign': [CHECKOUT, download('release-inputs', 'work/release-inputs'),
             upload('signed-release', 'work/signed-release')],
    **{f'installer-{leg}': [CHECKOUT, TOOLCHAIN, download('signed-release', 'work/signed-release'),
                            upload(f'installer-{leg}', f'work/installer-{leg}')] for leg in 'ab'},
    'verify': [CHECKOUT, download('signed-release', 'work/signed-release'), download('installer-a', 'work/installer-a'),
               download('installer-b', 'work/installer-b'), upload('unsigned-site', 'work/unsigned')],
    'finalize': [CHECKOUT, download('unsigned-site', 'work/unsigned'), upload('publication', 'work/publication')],
    'attest': [CHECKOUT, download('publication', 'work/publication'),
               ('actions/attest-build-provenance', {'subject-checksums': 'work/publication/assets/SHA256SUMS'}),
               ('actions/attest-build-provenance',
                {'subject-path': ''.join(f'work/publication/assets/{name}\n' for name in publish.release_assets('*'))})],
    'publish-release': [CHECKOUT, download('publication', 'work/publication')],
    'pages-build': [CHECKOUT, ('actions/upload-pages-artifact', {'path': 'work/pages/_site', 'retention-days': 7}),
                    upload('pages-record', 'work/pages-record')],
    'pages-deploy': [CHECKOUT, download('pages-record', 'work/pages-record'), ('actions/deploy-pages', None)],
    'verify-live': [CHECKOUT, download('publication', 'work/publication'),
                    download('pages-record', 'work/pages-record')],
}
REGISTRY = '--registry src/release/published-versions.json'
SITE = 'work/unsigned/site/$VERSION'
REPORT = 'work/unsigned/verification/verification-report.json'
GNUPG = '/dev/shm/intel-npu-release-gnupg'
# Every environment block, exactly: the workflow's, each job's and each step's. Another variable or value could change
# what a tool reads while every pinned call looks the same: the token, API host or repository of release_publish
# (GITHUB_API_URL, GITHUB_REPOSITORY and GITHUB_SHA come from the runner), the site budget or a bash start-up file.
# IMAGE_DIGEST is the image ci.yml pins, as every container's is.
CI_IMAGE = 'the image ci.yml pins'
RUST = {'CARGO_HOME': '/opt/ci-cargo', 'RUSTUP_HOME': '/opt/ci-rustup', 'RUSTUP_TOOLCHAIN': '1.85.0'}
KEYRING = {'RELEASE_GNUPGHOME': GNUPG, 'RELEASE_PUBLIC_KEY': 'src/crates/stack-install/src/trust/release-public.asc'}
TOKEN = '${{ github.token }}'
PROFILE = '${{ inputs.profile }}'
PUBLICATION = '${{ needs.finalize.outputs.publication_artifact }}'
PAGES_RECORD = '${{ needs.pages-build.outputs.pages_record_artifact }}'
SIGNED = '${{ needs.sign.outputs.signed_artifact }}'
ENV = {
    'workflow': {'SITE_BUDGET_BYTES': 314572800},
    'preflight': {**RUST, 'CARGO_BUILD_JOBS': 4, 'GH_TOKEN': TOKEN, 'INPUTS_URL': '${{ inputs.inputs_url }}',
                  'INPUTS_SHA256': '${{ inputs.inputs_sha256 }}', 'RELEASE_VERSION': '${{ inputs.release_version }}',
                  'PROFILE': PROFILE},
    'sign': {'INPUTS_SHA256': '${{ inputs.inputs_sha256 }}',
             'INPUTS_ARTIFACT': '${{ needs.preflight.outputs.inputs_artifact }}', 'PROFILE': PROFILE, **KEYRING},
    **{f'installer-{leg}': {'LEG': leg, 'LEG_UMASK': umask, 'TZ': zone, 'LANG': lang, 'CARGO_BUILD_JOBS': jobs, **RUST,
                            'IMAGE_DIGEST': CI_IMAGE, 'PROFILE': PROFILE, 'SIGNED_ARTIFACT': SIGNED}
       for leg, umask, zone, lang, jobs in [('a', '0022', 'UTC', 'C.UTF-8', 3),
                                            ('b', '0027', 'Pacific/Chatham', 'de_DE.UTF-8', 1)]},
    'verify': {'PROFILE': PROFILE, 'SIGNED_ARTIFACT': SIGNED,
               'LEG_A_ARTIFACT': '${{ needs.installer-a.outputs.installer_artifact }}',
               'LEG_B_ARTIFACT': '${{ needs.installer-b.outputs.installer_artifact }}'},
    'finalize': {'PROFILE': PROFILE, 'UNSIGNED_ARTIFACT': '${{ needs.verify.outputs.unsigned_artifact }}', **KEYRING},
    'attest': {'PUBLICATION_ARTIFACT': PUBLICATION},
    'publish-release': {'GH_TOKEN': TOKEN, 'PUBLICATION_ARTIFACT': PUBLICATION},
    'pages-build': {'GH_TOKEN': TOKEN},
    'pages-deploy': {'GH_TOKEN': TOKEN, 'PAGES_RECORD_ARTIFACT': PAGES_RECORD},
    'verify-live': {'PUBLICATION_ARTIFACT': PUBLICATION, 'PAGES_RECORD_ARTIFACT': PAGES_RECORD},
}
SIGNING_ENV = {'RELEASE_SIGNING_KEY': '${{ secrets.RELEASE_SIGNING_KEY }}',
               'RELEASE_SIGNING_PASSPHRASE': '${{ secrets.RELEASE_SIGNING_PASSPHRASE }}',
               'RELEASE_SIGNING_FINGERPRINT': '${{ vars.RELEASE_SIGNING_FINGERPRINT }}'}
STEP_ENV = {('sign', 'Import the signing key'): SIGNING_ENV, ('finalize', 'Import the signing key'): SIGNING_ENV}
# The committed version, for the later steps of a job: an assignment has the status of its command substitution, so a
# failed read stops the block before anything is written. `echo "VERSION=$(...)"` would write an empty VERSION and
# succeed.
VERSION_TO_ENV = ('VERSION="$(python3 src/scripts/ci/release_trust.py read --repo src --field version)" && '
                  'echo "VERSION=$VERSION" >> "$GITHUB_ENV"')
# A run block is one line of commands joined by `&&`, so it stops at the first command that fails. The shell does not
# check a tool whose output `$(...)` substitutes into an argument; the tool that receives the value refuses an empty
# one. Each command is a scripts/ci tool call, pinned in CALLS, a seal whose digest becomes a step output, or one of
# COMMANDS exactly as written. Anything else could skip a gate or ignore its refusal (`exit`, `||`, `;`, `&`, `!`),
# or change what a later tool reads (`export`, a redirect into $GITHUB_ENV). A seal names one plain work directory:
# step_calls pins only the tool call before a `;`, `|` or `||`, so a program after one would run unseen.
TOOL_COMMAND = re.compile(r'python3 src/scripts/ci/\w+\.py[^;&|<>`]*'
                          r'|python3 src/scripts/ci/release_artifact\.py seal (?:work/[\w-]+|"work/installer-\$LEG")'
                          r' >> "\$GITHUB_OUTPUT"')
# A command substitution in a tool call must run a scripts/ci tool of the checkout too, which step_calls records and
# CALLS pins. step_calls reads any other as `substituted`, so another program, such as one wrapped around a pinned
# read, would run unseen, even in a signing step while the key is present.
OTHER_SUBSTITUTION = re.compile(r'\$\((?!python3 src/scripts/ci/\w+\.py )')
COMMANDS = {
    'dnf5 --assumeyes --setopt=install_weak_deps=False install git ca-certificates',
    'dnf5 --assumeyes --setopt=install_weak_deps=False install createrepo_c',
    'bash src/scripts/ci/install-fedora-tools.sh',
    'cargo fetch --locked',
    'cargo run --locked -p xtask -- validate-profiles "$(dirname "$PROFILE")"',
    'bash src/scripts/ci/release-keyring.sh import',
    'bash src/scripts/ci/release-keyring.sh destroy',
    'umask "$LEG_UMASK"',
    *VERSION_TO_ENV.split(' && '),
    'mkdir -p work/release-inputs',
    'mkdir -p work/signed-release/records',
    'mkdir -p "work/installer-$LEG"',
    'mkdir -p work/unsigned/site work/unsigned/verification',
    'mkdir -p work/publication/assets',
    'mkdir -p work/pages work/pages-record',
    'mkdir -p work/live',
    'cp -a work/release-out/release-tree work/signed-release/',
    'cp work/release-out/provider-identity.json work/release-out/signed-identity.json '
    'work/release-out/profile-generation.json work/release-out/profile-rpm-build.json work/signed-release/records/',
    'cp "work/unsigned/site/$VERSION/SHA256SUMS" "work/unsigned/site/$VERSION/SHA256SUMS.asc" '
    '"work/unsigned/site/$VERSION/publication-manifest.json" work/publication/assets/',
}
# Every scripts/ci tool call of each job in the order it runs, a command substitution before the command that uses
# it: (tool, subcommand or None, arguments). Each call is a gate or a sealed handoff. The arguments are pinned
# because a tool refuses a missing required option, such as --registry or --reserve-bytes, only after argparse,
# where the parse test cannot see it.
CALLS = {
    'preflight': [
        ('release_inputs', 'dispatch-check', '--repo src --ref $GITHUB_REF --version $RELEASE_VERSION '
                                             '--url $INPUTS_URL --sha256 $INPUTS_SHA256 --profile $PROFILE'),
        ('release_inputs', 'fetch-check', '--url $INPUTS_URL --sha256 $INPUTS_SHA256 --profile src/$PROFILE '
                                          '--archive work/release-inputs/release-inputs.tar.gz '
                                          '--output work/inputs-check'),
        ('release_publish', 'check-unpublished', f'--phase preflight {REGISTRY} --reserve-bytes 314572800'),
        ('release_artifact', 'seal', 'work/release-inputs'),
    ],
    'sign': [
        ('release_artifact', 'check', 'work/release-inputs --digest $INPUTS_ARTIFACT'),
        ('release_inputs', 'extract-check', '--archive work/release-inputs/release-inputs.tar.gz '
                                            '--sha256 $INPUTS_SHA256 --expected $INPUTS_SHA256 --profile src/$PROFILE '
                                            '--output work/inputs'),
        ('release_trust', 'read', '--repo src --field primary-fingerprint'),
        ('release_trust', 'read', '--repo src --field base-url'),
        ('release_trust', 'read', '--repo src --field version'),
        ('release_sign', None, '--inputs work/inputs --profile src/$PROFILE --source src --output work/release-out '
                               f'--work work/release-work --fingerprint substituted --gpg-home {GNUPG} '
                               f'--passphrase-file {GNUPG}/passphrase --require-passphrase --base-url substituted '
                               '--release-version substituted'),
        ('check_release', None, '--release-tree work/release-out/release-tree --profile src/$PROFILE '
                                '--output work/tree-check.json'),
        ('release_artifact', 'seal', 'work/signed-release'),
    ],
    **{f'installer-{leg}': [
        ('release_artifact', 'check', 'work/signed-release --digest $SIGNED_ARTIFACT'),
        ('check_release', None, '--release-tree work/signed-release/release-tree --profile src/$PROFILE '
                                '--output work/tree-check.json'),
        ('release_installer', 'build', '--repo src --source-commit $GITHUB_SHA '
                                       f'--release-tree work/signed-release/release-tree --leg {leg} '
                                       f'--output work/installer-{leg}/leg'),
        ('release_artifact', 'seal', f'work/installer-{leg}'),
    ] for leg in 'ab'},
    'verify': [
        ('release_artifact', 'check', 'work/signed-release --digest $SIGNED_ARTIFACT'),
        ('release_artifact', 'check', 'work/installer-a --digest $LEG_A_ARTIFACT'),
        ('release_artifact', 'check', 'work/installer-b --digest $LEG_B_ARTIFACT'),
        ('release_trust', 'read', '--repo src --field version'),
        ('release_site', 'compose', '--source-commit $GITHUB_SHA --tree work/signed-release/release-tree '
                                    '--records work/signed-release/records --leg-a work/installer-a/leg '
                                    f'--leg-b work/installer-b/leg --profile src/$PROFILE --output {SITE}'),
        ('release_site', 'check', f'--source-commit $GITHUB_SHA --site {SITE} --profile src/$PROFILE '
                                  f'--stage unsigned --max-bytes 314572800 --report {REPORT}'),
        ('release_serve', 'serve-test', f'--site-root work/unsigned/site --expected-files {REPORT} '
                                        '--report work/unsigned/verification/serve-report.json --work work/serve'),
        ('release_artifact', 'seal', 'work/unsigned'),
    ],
    'finalize': [
        ('release_artifact', 'check', 'work/unsigned --digest $UNSIGNED_ARTIFACT'),
        ('release_trust', 'read', '--repo src --field version'),
        ('release_site', 'check', f'--source-commit $GITHUB_SHA --site {SITE} --profile src/$PROFILE '
                                  '--stage unsigned'),
        ('release_trust', 'read', '--repo src --field primary-fingerprint'),
        ('release_site', 'sign', f'--source-commit $GITHUB_SHA --site {SITE} --profile src/$PROFILE '
                                 f'--expected-files {REPORT} --gpg-home {GNUPG} --fingerprint substituted '
                                 f'--passphrase-file {GNUPG}/passphrase --require-passphrase'),
        ('release_site', 'check', f'--source-commit $GITHUB_SHA --site {SITE} --profile src/$PROFILE '
                                  f'--stage signed --expected-files {REPORT} --max-bytes 314572800'),
        ('release_site', 'archive', f'--source-commit $GITHUB_SHA --site {SITE} --profile src/$PROFILE '
                                    f'--expected-files {REPORT} '
                                    '--output work/publication/assets/intel-npu-stack-$VERSION.tar'),
        ('release_site', 'notes', f'--site {SITE} --archive work/publication/assets/intel-npu-stack-$VERSION.tar '
                                  '--output work/publication/notes.md'),
        ('release_artifact', 'seal', 'work/publication'),
    ],
    'attest': [
        ('release_artifact', 'check', 'work/publication --digest $PUBLICATION_ARTIFACT'),
    ],
    'publish-release': [
        ('release_artifact', 'check', 'work/publication --digest $PUBLICATION_ARTIFACT'),
        ('release_publish', 'check-unpublished', f'--phase publish {REGISTRY} --assets work/publication/assets '
                                                 '--sha $GITHUB_SHA'),
        ('release_publish', 'publish-release', f'{REGISTRY} --assets work/publication/assets '
                                               '--notes work/publication/notes.md --sha $GITHUB_SHA'),
    ],
    'pages-build': [
        ('release_trust', 'read', '--repo src --field version'),
        ('release_publish', 'compose-pages', f'{REGISTRY} --output work/pages/_site '
                                             '--manifest work/pages-record/pages-manifest.json '
                                             '--new-version substituted'),
        ('release_artifact', 'seal', 'work/pages-record'),
    ],
    'pages-deploy': [
        ('release_artifact', 'check', 'work/pages-record --digest $PAGES_RECORD_ARTIFACT'),
        ('release_publish', 'check-deploy', f'{REGISTRY} --pages-manifest work/pages-record/pages-manifest.json'),
    ],
    'verify-live': [
        ('release_artifact', 'check', 'work/publication --digest $PUBLICATION_ARTIFACT'),
        ('release_artifact', 'check', 'work/pages-record --digest $PAGES_RECORD_ARTIFACT'),
        ('release_trust', 'read', '--repo src --field version'),
        ('release_publish', 'verify-live', '--archive work/publication/assets/intel-npu-stack-$VERSION.tar '
                                           '--pages-manifest work/pages-record/pages-manifest.json '
                                           '--sha $GITHUB_SHA --fetched work/live'),
        ('release_serve', 'serve-test', '--live --site-root work/live --report work/live-serve.json '
                                        '--work work/live-serve'),
    ],
}
# The only conditions a job or step may carry, in the order they run, each with its reason: (job, step, condition,
# reason), each step right after its job's SIGNING_STEPS entry. Any other `if:`, braced or not, could skip a gate or
# let a later step run after one failed.
CONDITIONS = [
    ('sign', 'Destroy the signing keyring', 'always()', 'the keyring is destroyed even when signing fails'),
    ('finalize', 'Destroy the signing keyring', 'always()', 'the keyring is destroyed even when signing fails'),
]
# The keys a step may have, those of a run block or of an action; ACTIONS, CONDITIONS, STEP_ENV and
# WORKING_DIRECTORIES pin the inputs, conditions, env and directories. Any other key, such as a step's shell or
# continue-on-error, changes how the step runs while every pinned call looks the same.
STEP_KEYS = {'run': {'name', 'id', 'if', 'env', 'working-directory', 'run'},
             'uses': {'name', 'id', 'if', 'env', 'uses', 'with'}}
# The only step that runs outside the workspace, where each tool and script path names the checkout's file: the
# profile validation runs cargo in the checkout. Run from the fetched inputs, a Destroy step would run their keyring
# script while the key is still present, and a gate their copy of its tool.
WORKING_DIRECTORIES = {('preflight', 'Validate the profiles with the canonical schema validator'): 'src'}


def load(name):
    text = (REPO / '.github/workflows' / name).read_text()
    return text, yaml.safe_load(text)


def steps_of(job):
    return job.get('steps', [])


def run_text(job, step):
    """A step's run block with the job's LEG expanded, so both installer legs read as their own paths."""
    text = step.get('run', '').replace('"', '')
    leg = job.get('env', {}).get('LEG')
    return text.replace('$LEG', leg) if leg else text


def unquoted(text):
    """What in a run block bash could read otherwise than step_calls, which expands before it removes quotes: a single
    quote, backslash or backquote, a parenthesis that opens no command substitution, a `$` outside double quotes or
    a quote left open. As in bash, a command substitution quotes afresh: "$(dirname "$PROFILE")" quotes both."""
    found = [char for char in "'\\`" if char in text] + re.findall(r'(?<!\$)\(', text)
    quoted = [False]  # one entry per open command substitution
    for index, char in enumerate(text):
        if char == '"':
            quoted[-1] = not quoted[-1]
        elif char == '$':
            if not quoted[-1]:
                found.append(text[index:].split()[0])
            if text.startswith('$(', index):
                quoted.append(False)
        elif char == ')' and len(quoted) > 1 and not quoted[-1]:
            quoted.pop()
    return found + (['an open quote or command substitution'] if quoted != [False] else [])


def step_calls(workflow, job, step):
    """(tool, argv) for every scripts/ci tool a run block calls, in the order they run, with literal environment
    values expanded; a command substitution runs before the command that uses it and reads as `substituted`. Bash
    passes the same argv because every expansion is double-quoted and nothing else is quoted (unquoted())."""
    env = {**workflow.get('env', {}), **job.get('env', {}), **step.get('env', {})}
    literal = {key: str(value) for key, value in env.items() if '${{' not in str(value)}
    text = re.sub(r'\\\n\s*', ' ', step.get('run', ''))
    text = SHELL_VARIABLE.sub(lambda match: literal.get(match.group(1), match.group(0)), text)
    nested = []
    while match := NESTED.search(text):
        nested.append(match.group(1))
        text = text[:match.start()] + f'substituted{len(nested) - 1}' + text[match.end():]

    def in_order(command):
        for index in SUBSTITUTED.findall(command):
            yield from in_order(nested[int(index)])
        yield SUBSTITUTED.sub('substituted', command)
    calls = []
    for command in re.split(r'&&|\|\||;|>>|\||\n', text):
        for part in in_order(command):
            if match := TOOL.match(part.strip()):
                calls.append((match.group(1), shlex.split(part)[2:]))
    return calls


def tool_calls(workflow):
    """(job, tool, argv) for every scripts/ci tool call of every job, in the order each job runs them."""
    return [(name, tool, argv) for name, job in workflow['jobs'].items() for step in steps_of(job)
            for tool, argv in step_calls(workflow, job, step)]


def pinned(tool, argv):
    """A tool call as CALLS lists it: (tool, subcommand or None, arguments)."""
    subcommand = argv[0] if argv and not argv[0].startswith('-') else None
    return tool, subcommand, ' '.join(argv[1:] if subcommand else argv)


def strings(node):
    """Every string key and value of a parsed workflow, as GitHub evaluates them after YAML folds and escapes."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from strings(key)
            yield from strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from strings(item)
    elif isinstance(node, str):
        yield node


def actions_used(node):
    """Every `uses` of a parsed workflow, wherever it stands: a step's action or a job's reusable workflow."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from [value] if key == 'uses' else actions_used(value)
    elif isinstance(node, list):
        for item in node:
            yield from actions_used(item)


@unittest.skipIf(yaml is None, 'PyYAML is required')
class ReleaseWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.workflow = load('release.yml')
        cls.jobs = cls.workflow['jobs']
        _, ci = load('ci.yml')
        cls.image = ci['jobs']['quality']['container']['image']

    def calls(self):
        """{job: [(tool, subcommand or None, arguments)]} as the workflow makes them."""
        made = {name: [] for name in self.jobs}
        for name, tool, argv in tool_calls(self.workflow):
            made[name].append(pinned(tool, argv))
        return made

    def test_no_default_permissions_and_one_global_concurrency_group(self):
        self.assertEqual(self.workflow['permissions'], {})
        self.assertEqual(self.workflow['concurrency'], {'group': 'release-publication', 'cancel-in-progress': False})
        self.assertEqual(self.workflow['defaults'], {'run': {'shell': 'bash'}})
        self.assertEqual(list(self.workflow[True]), ['workflow_dispatch'])  # PyYAML reads `on` as True
        self.assertEqual(set(self.workflow[True]['workflow_dispatch']['inputs']),
                         {'inputs_url', 'inputs_sha256', 'release_version', 'profile'})

    def test_exact_jobs_and_permissions(self):
        self.assertEqual({name: job.get('permissions') for name, job in self.jobs.items()}, JOBS)

    def test_every_job_runs_once_on_a_fresh_github_hosted_runner(self):
        for name, job in self.jobs.items():
            self.assertEqual(job.get('runs-on'), RUNNER, name)
            self.assertLessEqual(set(job), JOB_KEYS, name)

    def test_every_step_name_is_unique_within_its_job(self):
        # Several invariants find a step by its name, so a second step of that name could hide behind the first.
        for name, job in self.jobs.items():
            names = [step['name'] for step in steps_of(job) if 'name' in step]
            self.assertEqual(len(names), len(set(names)), name)

    def test_environments_gate_only_the_key_jobs_and_the_pages_deployment(self):
        environments = {name: job.get('environment') for name, job in self.jobs.items() if 'environment' in job}
        self.assertEqual(set(environments), KEY_JOBS | {'pages-deploy'})
        for name in KEY_JOBS:
            self.assertEqual(environments[name], 'release')
        self.assertEqual(environments['pages-deploy']['name'], 'github-pages')

    def test_secrets_appear_only_in_the_import_steps_of_the_key_jobs(self):
        imports = [('sign', 'Import the signing key'), ('finalize', 'Import the signing key')]
        self.assertEqual([(name, step.get('name', step.get('uses'))) for name, job in self.jobs.items()
                          for step in steps_of(job) if 'secrets.' in str(step)], imports)
        for name, label in imports:
            step = next(step for step in steps_of(self.jobs[name]) if step.get('name') == label)
            self.assertEqual(set(step), {'name', 'env', 'run'})
            self.assertEqual(step['env'], SIGNING_ENV)
            self.assertEqual(step['run'].strip(), 'bash src/scripts/ci/release-keyring.sh import')
        # Nowhere else: not the workflow or a job env, a container, a service, an action input or another step.
        rest = {**self.workflow, 'jobs': {name: {**job, 'steps': [step for step in steps_of(job)
                                                                  if (name, step.get('name')) not in imports]}
                                          for name, job in self.jobs.items()}}
        self.assertNotIn('secrets.', str(rest))

    def test_key_jobs_check_before_the_key_and_always_destroy_it(self):
        for name in KEY_JOBS:
            job = self.jobs[name]
            steps = steps_of(job)
            names = [step.get('name', step.get('uses', '')) for step in steps]
            imported, destroyed = names.index('Import the signing key'), names.index('Destroy the signing keyring')
            self.assertTrue(any(name.startswith('Check') for name in names[:imported]), name)
            # Only the signing step runs with the key present, since any other step, an action or a run block, could
            # read or copy the keyring and the passphrase file. That step is one command, the signing tool with the
            # reads it substitutes and no other program (OTHER_SUBSTITUTION), and SIGNING_CALLS pins its tool calls.
            # With CALLS, every other call of the job, each gate that needs no key, runs before Import or after
            # Destroy, and so does every other command.
            self.assertEqual(names[imported + 1:destroyed], [SIGNING_STEPS[name]], name)
            self.assertEqual(set(steps[imported + 1]), {'name', 'run'}, name)
            self.assertNotIn('&&', steps[imported + 1]['run'], name)
            self.assertNotRegex(steps[imported + 1]['run'], OTHER_SUBSTITUTION, name)
            signing = step_calls(self.workflow, job, steps[imported + 1])
            self.assertEqual([pinned(tool, argv)[:2] for tool, argv in signing], SIGNING_CALLS[name], name)
            self.assertEqual(steps[destroyed]['if'], 'always()')
            self.assertEqual(steps[destroyed]['run'].strip(), 'bash src/scripts/ci/release-keyring.sh destroy')

    def test_key_jobs_build_nothing_and_hold_no_write_token(self):
        for name in KEY_JOBS:
            job = self.jobs[name]
            for word in ['cargo', 'rust-toolchain', 'xtask', 'GH_TOKEN', 'github.token']:
                # The workflow env reaches every step of the job too.
                self.assertNotIn(word, str(self.workflow.get('env', {})) + str(job), f'{name} mentions {word}')
            for step in steps_of(job):
                if 'uses' in step:
                    self.assertTrue(step['uses'].startswith(KEY_JOB_ACTIONS), f"{name} runs {step['uses']}")
        self.assertNotIn('guest-harness', self.text)

    def test_every_action_is_pinned_to_a_commit(self):
        uses = re.findall(r'uses:\s*(\S+)', self.text)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$')

    def test_every_use_of_an_action_in_any_workflow_has_the_same_commit(self):
        # ACTIONS pins each action by name. One commit per action across every workflow means no single pin, such as
        # that of a key job's checkout or artifact download, can change without all the other uses of that action.
        # GitHub reads the owner and repository of a name in any case, so names are compared in lower case, and a
        # name has no empty, `.` or `..` segment, which could be another spelling of the same action.
        commits = {}
        for path in sorted((REPO / '.github/workflows').iterdir()):
            if path.suffix in {'.yml', '.yaml'}:
                for uses in actions_used(yaml.safe_load(path.read_text())):
                    match = re.fullmatch(r'([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)@([0-9a-f]{40})', str(uses))
                    self.assertIsNotNone(match, f'{path.name}: {uses}')
                    self.assertFalse({'.', '..'} & set(match.group(1).split('/')), f'{path.name}: {uses}')
                    commits.setdefault(match.group(1).lower(), set()).add(match.group(2))
        self.assertLessEqual({action for actions in ACTIONS.values() for action, _ in actions}, set(commits))
        self.assertEqual({action: sorted(pins) for action, pins in commits.items() if len(pins) > 1}, {})

    def test_every_job_runs_exactly_its_actions_with_their_inputs(self):
        # An input such as a checkout's ref, repository or persist-credentials, or the path of the Pages artifact,
        # changes what the job runs or serves as surely as another action would.
        self.assertEqual({name: [(step['uses'].split('@')[0], step.get('with')) for step in steps_of(job)
                                 if 'uses' in step] for name, job in self.jobs.items()}, ACTIONS)

    def test_every_container_uses_the_ci_image(self):
        # Nothing runs beside a job and nothing reaches its steps but the pinned env: no service, and a container of
        # just the image and the CPU limit. verify also resolves the Pages host to its local fixture. attest and
        # pages-deploy run on the runner itself.
        self.assertEqual({name for name, job in self.jobs.items() if 'container' not in job},
                         {'attest', 'pages-deploy'})
        for name, job in self.jobs.items():
            self.assertNotIn('services', job, name)
            if 'container' in job:
                options = '--cpus 4 --add-host archledger.github.io:127.0.0.1' if name == 'verify' else '--cpus 4'
                self.assertEqual(job['container'], {'image': self.image, 'options': options}, name)

    def test_every_environment_is_pinned(self):
        blocks = {'workflow': self.workflow.get('env'), **{name: job.get('env') for name, job in self.jobs.items()}}
        steps = {(name, step.get('name')): step['env'] for name, job in self.jobs.items() for step in steps_of(job)
                 if 'env' in step}
        for env in [*blocks.values(), *steps.values()]:
            self.assertFalse([key for key in env or {} if key.startswith(('GITHUB_', 'RUNNER_'))], 'set by the runner')
        self.assertEqual(blocks, {name: {key: self.image if value == CI_IMAGE else value for key, value in env.items()}
                                  for name, env in ENV.items()})
        self.assertEqual(steps, STEP_ENV)

    def test_every_run_block_stops_at_its_first_failure(self):
        for name, job in self.jobs.items():
            for step in steps_of(job):
                if 'run' in step:
                    with self.subTest(job=name, step=step.get('name')):
                        self.assertNotIn('\n', step['run'])  # one line: a block folds its lines with `>-`
                        for command in step['run'].split(' && '):
                            self.assertTrue(command in COMMANDS or TOOL_COMMAND.fullmatch(command), command)
                            if command not in COMMANDS:
                                self.assertNotRegex(command, OTHER_SUBSTITUTION)

    def test_run_blocks_double_quote_every_expansion(self):
        # step_calls expands the environment before it removes quotes. With '$SITE_BUDGET_BYTES' or \$GITHUB_SHA the
        # pinned calls and the parse test would see the value where bash passes the name, and with an unquoted
        # $PROFILE one argument where bash splits and globs the value.
        for name, job in self.jobs.items():
            for step in steps_of(job):
                with self.subTest(job=name, step=step.get('name')):
                    self.assertEqual(unquoted(step.get('run', '')), [])

    def test_later_steps_read_only_the_committed_version_from_the_environment_file(self):
        # A write to $GITHUB_ENV sets the environment of every later step of the job, such as the site budget both
        # tools read, while every pinned call looks the same. Each write comes right after the read it writes.
        # Nothing writes $GITHUB_PATH.
        writes = []
        for name, job in self.jobs.items():
            for step in steps_of(job):
                commands = step.get('run', '').split(' && ')
                writes += [(name, ' && '.join(commands[max(index - 1, 0):index + 1]))
                           for index, command in enumerate(commands) if 'GITHUB_ENV' in command]
        self.assertEqual(writes, [(name, VERSION_TO_ENV) for name in ['verify', 'finalize', 'verify-live']])
        self.assertNotIn('GITHUB_PATH', self.text)

    def test_a_failed_version_read_stops_its_block_before_the_environment_file(self):
        # bash as the runner starts it for `shell: bash`, with the committed version read by a stand-in tool.
        for label, tool, status, written in [
                ('read', 'print("0.1.0")', 0, 'VERSION=0.1.0\n'),
                ('refused', 'raise SystemExit(1)', 1, None),
                ('refused after printing', 'print("0.1.0")\nraise SystemExit(3)', 3, None)]:
            with self.subTest(label), tempfile.TemporaryDirectory(prefix='version-to-env-') as work:
                stand_in = Path(work, 'src/scripts/ci/release_trust.py')
                stand_in.parent.mkdir(parents=True)
                stand_in.write_text(tool + '\n')
                environment = Path(work, 'github-env')
                run = subprocess.run(['bash', '--noprofile', '--norc', '-eo', 'pipefail', '-c', VERSION_TO_ENV],
                                     cwd=work, capture_output=True, text=True,
                                     env={'PATH': os.environ['PATH'], 'GITHUB_ENV': str(environment)})
                self.assertEqual(run.returncode, status, run.stderr)
                self.assertEqual(environment.read_text() if environment.exists() else None, written)

    def test_run_blocks_never_expand_expressions(self):
        for name, job in self.jobs.items():
            for step in steps_of(job):
                self.assertNotIn('${{', step.get('run', ''), f"{name}: {step.get('name')}")

    def test_expressions_stay_in_the_supported_subset(self):
        # The parsed values too: a line fold or a quoted escape can form an expression the file text does not show.
        for text in [self.text, *strings(self.workflow)]:
            for expression in re.findall(EXPRESSION.pattern, text, re.DOTALL):
                self.assertRegex(expression, '^(' + ALLOWED.pattern + ')$')
            self.assertNotIn('${{', re.sub(EXPRESSION.pattern, '', text, flags=re.DOTALL))

    def test_no_condition_or_error_tolerance_can_skip_a_gate(self):
        # Every step runs in the workflow's bash, which stops at the first failure; a job's defaults or a step's
        # shell could run it with another shell, or with none. test_every_run_block_stops_at_its_first_failure
        # covers the commands themselves. The conditions are listed in order with the step before each, so a second
        # step of the same name, or a Destroy step moved elsewhere, cannot take the place of the one allowed.
        conditions = []
        for name, job in self.jobs.items():
            self.assertFalse({'if', 'continue-on-error', 'defaults'} & set(job), name)
            steps = steps_of(job)
            for index, step in enumerate(steps):
                self.assertFalse({'continue-on-error', 'shell'} & set(step), f"{name}: {step.get('name')}")
                if 'if' in step:
                    conditions.append((name, steps[index - 1].get('name') if index else None,
                                       step.get('name', step.get('uses')), step['if']))
        self.assertEqual(conditions, [(name, SIGNING_STEPS[name], label, condition)
                                      for name, label, condition, _ in CONDITIONS])

    def test_every_step_has_only_pinned_keys_and_runs_in_the_workspace(self):
        directories = {}
        for name, job in self.jobs.items():
            for step in steps_of(job):
                label = f"{name}: {step.get('name', step.get('uses'))}"
                self.assertLessEqual(set(step), STEP_KEYS['run' if 'run' in step else 'uses'], label)
                if 'working-directory' in step:
                    directories[(name, step.get('name'))] = step['working-directory']
        self.assertEqual(directories, WORKING_DIRECTORIES)

    def test_installer_legs_are_identical_but_for_the_perturbation(self):
        first, second = self.jobs['installer-a'], self.jobs['installer-b']

        def normalized(job):
            text = str({key: value for key, value in job.items() if key not in {'name', 'env'}})
            return text.replace('installer-a', 'installer-X').replace('installer-b', 'installer-X')
        self.assertEqual(normalized(first), normalized(second))
        env_a, env_b = first['env'], second['env']
        self.assertEqual({k: v for k, v in env_a.items() if k not in LEG_PERTURBATIONS},
                         {k: v for k, v in env_b.items() if k not in LEG_PERTURBATIONS})
        for key in LEG_PERTURBATIONS:
            self.assertNotEqual(env_a[key], env_b[key], key)
        self.assertEqual((env_a['LEG'], env_b['LEG']), ('a', 'b'))
        self.assertLessEqual(int(env_b['CARGO_BUILD_JOBS']), 4)

    def test_jobs_that_can_run_at_once_share_four_build_jobs(self):
        # The repository allows four build jobs in total. Jobs that do not wait for each other can run at the same
        # time, as the two installer legs do after sign, so every set of such jobs shares the four. A job that builds
        # sets CARGO_BUILD_JOBS: cargo would otherwise use every CPU and the installer build its maximum of four.
        needs = {name: {job['needs']} if isinstance(job.get('needs'), str) else set(job.get('needs', []))
                 for name, job in self.jobs.items()}

        def waits_for(name):
            found, pending = set(), list(needs[name])
            while pending:
                other = pending.pop()
                if other not in found:
                    found.add(other)
                    pending.extend(needs[other])
            return found
        before = {name: waits_for(name) for name in self.jobs}
        builds = {}
        for name, job in self.jobs.items():
            text = ' '.join(run_text(job, step) for step in steps_of(job))
            if re.search(r'\bcargo\s|release_installer\.py build', text):
                self.assertIn('CARGO_BUILD_JOBS', job.get('env', {}), name)
            builds[name] = int(job.get('env', {}).get('CARGO_BUILD_JOBS', 0))
        builders = [name for name in self.jobs if builds[name]]
        self.assertEqual(builders, ['preflight', 'installer-a', 'installer-b'])
        for count in range(1, len(builders) + 1):
            for group in itertools.combinations(builders, count):
                if all(first not in before[second] and second not in before[first]
                       for first, second in itertools.combinations(group, 2)):
                    self.assertLessEqual(sum(builds[name] for name in group), 4, group)

    def test_artifacts_are_short_lived_and_every_download_is_checked(self):
        # A download is checked by the first step after it that downloads nothing, before any other step or action
        # reads it: attest must not attest files the handoff check has not accepted yet.
        for name, job in self.jobs.items():
            steps = steps_of(job)
            for index, step in enumerate(steps):
                uses = step.get('uses', '')
                if uses.startswith(('actions/upload-artifact@', 'actions/upload-pages-artifact@')):
                    self.assertLessEqual(step['with']['retention-days'], 7, name)
                if uses.startswith('actions/download-artifact@'):
                    path = step['with']['path']
                    following = next((later for later in steps[index + 1:]
                                      if not later.get('uses', '').startswith('actions/download-artifact@')), {})
                    self.assertIn(f'release_artifact.py check {path} ', run_text(job, following),
                                  f'{name} does not check {path} right after downloading it')

    def test_every_uploaded_artifact_is_sealed_first(self):
        # The Pages artifact is the exception: upload-pages-artifact hands it straight to deploy-pages (ACTIONS pins
        # both), and check-deploy checks the sealed pages-record that describes it, not the tree.
        for name, job in self.jobs.items():
            for index, step in enumerate(steps_of(job)):
                if step.get('uses', '').startswith('actions/upload-artifact@'):
                    path = step['with']['path']
                    self.assertTrue(any(f'release_artifact.py seal {path}' in run_text(job, before)
                                        for before in steps_of(job)[:index]), f'{name} does not seal {path}')

    def test_publication_order(self):
        self.assertEqual(self.jobs['publish-release']['needs'], ['finalize', 'attest'])
        self.assertEqual(self.jobs['pages-build']['needs'], 'publish-release')
        self.assertEqual(self.jobs['pages-deploy']['needs'], 'pages-build')
        self.assertIn('pages-deploy', self.jobs['verify-live']['needs'])
        self.assertIn('--add-host archledger.github.io:127.0.0.1', self.jobs['verify']['container']['options'])

    def test_the_preflight_validates_the_profiles_before_it_fetches_the_inputs(self):
        runs = [step.get('run', '') for step in steps_of(self.jobs['preflight'])]
        validate = [index for index, run in enumerate(runs)
                    if 'cargo run --locked -p xtask -- validate-profiles' in run]
        fetch = [index for index, run in enumerate(runs) if 'release_inputs.py fetch-check' in run]
        self.assertEqual((len(validate), len(fetch)), (1, 1))
        self.assertLess(validate[0], fetch[0])

    def test_every_job_makes_exactly_its_gate_calls_in_order(self):
        # A gate that is deleted, added or moved must show up here as a reviewed change.
        self.assertEqual({name: [call[:2] for call in calls] for name, calls in self.calls().items()},
                         {name: [call[:2] for call in calls] for name, calls in CALLS.items()})

    def test_every_tool_call_passes_exactly_its_pinned_arguments(self):
        made = self.calls()
        self.assertEqual(set(made), set(CALLS))
        for name, calls in CALLS.items():
            with self.subTest(job=name):
                self.assertEqual(made[name], calls)

    def test_the_preflight_reserves_the_site_budget_verify_enforces(self):
        # The room check reserves bytes for a site that is not built yet. verify refuses an unsigned site that would
        # not fit them once signed, finalize holds the signed site to them, and the publication steps repeat the room
        # check with the signed site's real size.
        def option(job, tool, subcommand, name, stage=None):
            made = [argv for made_in, made_by, argv in tool_calls(self.workflow)
                    if (made_in, made_by, argv[0]) == (job, tool, subcommand)
                    and (stage is None or argv[argv.index('--stage') + 1] == stage)]
            self.assertEqual(len(made), 1, f'{job} makes one {tool} {subcommand} call')
            self.assertIn(name, made[0], f'{job}: {tool} {subcommand}')
            return made[0][made[0].index(name) + 1]
        budget = self.workflow['env']['SITE_BUDGET_BYTES']
        self.assertTrue(type(budget) is int and 0 < budget <= publish.MAX_SITE)
        self.assertEqual((option('preflight', 'release_publish', 'check-unpublished', '--reserve-bytes'),
                          option('verify', 'release_site', 'check', '--max-bytes'),
                          option('finalize', 'release_site', 'check', '--max-bytes', stage='signed')),
                         (str(budget), str(budget), str(budget)))
        self.assertFalse([name for name, job in self.jobs.items() if 'SITE_BUDGET_BYTES' in job.get('env', {})],
                         'the budget is defined once, for the whole workflow')

    def test_the_composition_is_checked_right_before_it_is_deployed(self):
        # A re-run of an older run's pages-deploy reuses that run's Pages artifact; only a check in this job, right
        # before the deployment, can tell whether its composition is still current.
        job = self.jobs['pages-deploy']
        steps = steps_of(job)
        self.assertTrue(steps[-1].get('uses', '').startswith('actions/deploy-pages@'))
        self.assertEqual([(tool, argv[0]) for tool, argv in step_calls(self.workflow, job, steps[-2])],
                         [('release_publish', 'check-deploy')])

    def test_every_tool_call_parses_under_the_tool_arguments(self):
        class Parsed(Exception):
            pass
        original = argparse.ArgumentParser.parse_args

        def parse_only(parser, args=None, namespace=None):
            # Options must be spelled in full: an abbreviation breaks once another option shares its prefix.
            parser.allow_abbrev = False
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    for subparser in action.choices.values():
                        subparser.allow_abbrev = False
            raise Parsed(original(parser, args, namespace))
        calls = tool_calls(self.workflow)
        runs = [step.get('run', '') for job in self.jobs.values() for step in steps_of(job)]
        self.assertEqual(len(calls), sum(len(TOOL_MENTION.findall(run)) for run in runs))
        self.assertGreater(len(calls), 0)
        with mock.patch.object(argparse.ArgumentParser, 'parse_args', parse_only):
            for name, tool, argv in calls:
                with self.subTest(job=name, tool=tool, argv=argv):
                    errors = io.StringIO()
                    try:
                        with contextlib.redirect_stderr(errors):
                            importlib.import_module(tool).main(argv)
                    except Parsed:
                        continue
                    except SystemExit:
                        pass
                    self.fail(f'{name}: {tool} {" ".join(argv)}: {errors.getvalue().strip()}')


if __name__ == '__main__':
    unittest.main()
