#!/usr/bin/python3
"""Build cephadm from one or more files into a standalone executable.
"""
# TODO: If cephadm is being built and packaged within a format such as RPM
# do we have to do anything special wrt passing in the version
# of python to build with? Even with the intermediate cmake layer?

import argparse
import compileall
import enum
import json
import logging
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile

HAS_ZIPAPP = False
try:
    import zipapp

    HAS_ZIPAPP = True
except ImportError:
    pass


log = logging.getLogger(__name__)


PY36_REQUIREMENTS = [
    'MarkupSafe >= 2.0.1, <2.2',
    'Jinja2 >= 3.0.2, <3.2',
]
PY_REQUIREMENTS = [
    'MarkupSafe >= 2.1.3, <2.2',
    'Jinja2 >= 3.1.2, <3.2',
]
# IMPORTANT to be fully compatible with all the distros ceph is built for we
# need to work around various old versions of python/pip. As such it's easier
# to repeat our requirements in this script than it is to parse zipapp-reqs.txt.
# You *must* keep the PY_REQUIREMENTS list in sync with the contents of
# zipapp-reqs.txt manually.

_VALID_VERS_VARS = [
    "CEPH_GIT_VER",
    "CEPH_GIT_NICE_VER",
    "CEPH_RELEASE",
    "CEPH_RELEASE_NAME",
    "CEPH_RELEASE_TYPE",
]


class PipEnv(enum.Enum):
    never = enum.auto()
    auto = enum.auto()
    required = enum.auto()

    @property
    def enabled(self):
        return self == self.auto or self == self.required


class DependencyMode(enum.Enum):
    pip = enum.auto()
    rpm = enum.auto()
    none = enum.auto()


class Config:
    def __init__(self, cli_args):
        self.cli_args = cli_args
        self._maj_min = sys.version_info[0:2]
        self.install_dependencies = True
        self.deps_mode = DependencyMode[cli_args.bundled_dependencies]
        if self.deps_mode == DependencyMode.none:
            self.install_dependencies = False
        if self.deps_mode == DependencyMode.pip:
            self._setup_pip()
        elif self.deps_mode == DependencyMode.rpm:
            self._setup_rpm()

    def _setup_pip(self):
        if self._maj_min == (3, 6):
            self.pip_split = True
            self.requirements = PY36_REQUIREMENTS
        else:
            self.pip_split = False
            self.requirements = PY_REQUIREMENTS
        self.pip_venv = PipEnv[self.cli_args.pip_use_venv]

    def _setup_rpm(self):
        self.requirements = [s.split()[0] for s in PY_REQUIREMENTS]


class DependencyInfo:
    """Type for tracking bundled dependencies."""

    def __init__(self, config):
        self._config = config
        self._deps = []
        self._reqs = {s.split()[0]: s for s in self._config.requirements}

    @property
    def requirements(self):
        """Return requirements."""
        return self._config.requirements

    def add(self, name, **fields):
        """Add a new bundled dependency to track."""
        vals = {'name': name}
        vals.update({k: v for k, v in fields.items() if v is not None})
        if name in self._reqs:
            vals['requirements_entry'] = self._reqs[name]
        self._deps.append(vals)

    def save(self, path):
        """Record bundled dependency meta-data to the supplied file."""
        with open(path, 'w') as fh:
            json.dump(self._deps, fh)



def _run(command, *args, **kwargs):
    log.info(
        'Running cmd: %s', ' '.join(shlex.quote(str(c)) for c in command)
    )
    return subprocess.run(command, *args, **kwargs)


def _reexec(python):
    """Switch to the selected version of python by exec'ing into the desired
    python path.
    Sets the _BUILD_PYTHON_SET env variable as a sentinel to indicate exec has
    been performed.
    """
    env = os.environ.copy()
    env["_BUILD_PYTHON_SET"] = python
    os.execvpe(python, [python, __file__] + sys.argv[1:], env)


def _did_rexec():
    """Returns true if the process has already exec'ed into the desired python
    version.
    """
    return bool(os.environ.get("_BUILD_PYTHON_SET", ""))


def _build(dest, src, config):
    """Build the binary."""
    os.chdir(src)
    tempdir = pathlib.Path(tempfile.mkdtemp(suffix=".cephadm.build"))
    log.debug("working in %s", tempdir)
    dinfo = None
    try:
        if config.install_dependencies:
            dinfo = _install_deps(tempdir, config)
        log.info("Copying contents")
        # cephadmlib is cephadm's private library of modules
        shutil.copytree(
            "cephadmlib", tempdir / "cephadmlib", ignore=_ignore_cephadmlib
        )
        # cephadm.py is cephadm's main script for the "binary"
        # this must be renamed to __main__.py for the zipapp
        shutil.copy("cephadm.py", tempdir / "__main__.py")
        mdir = tempdir / "_cephadmmeta"
        mdir.mkdir(parents=True, exist_ok=True)
        (mdir / "__init__.py").touch(exist_ok=True)
        versioning_vars = config.cli_args.version_vars
        if versioning_vars:
            generate_version_file(versioning_vars, mdir / "version.py")
        if dinfo:
            dinfo.save(mdir / "deps.json")
        _compile(dest, tempdir)
    finally:
        shutil.rmtree(tempdir)


def _ignore_cephadmlib(source_dir, names):
    # shutil.copytree callback: return the list of names *to ignore*
    return [
        name
        for name in names
        if name.endswith(
            ("~", ".old", ".swp", ".pyc", ".pyo", ".so", "__pycache__")
        )
    ]


def _compile(dest, tempdir):
    """Compile the zipapp."""
    log.info("Byte-compiling py to pyc")
    compileall.compile_dir(
        tempdir,
        maxlevels=16,
        legacy=True,
        quiet=1,
        workers=0,
    )
    # TODO we could explicitly pass a python version here
    log.info("Constructing the zipapp file")
    try:
        zipapp.create_archive(
            source=tempdir,
            target=dest,
            interpreter=sys.executable,
            compressed=True,
        )
        log.info("Zipapp created with compression")
    except TypeError:
        # automatically fall back to uncompressed
        zipapp.create_archive(
            source=tempdir,
            target=dest,
            interpreter=sys.executable,
        )
        log.info("Zipapp created without compression")


def _install_deps(tempdir, config):
    if config.deps_mode == DependencyMode.pip:
        return _install_pip_deps(tempdir, config)
    if config.deps_mode == DependencyMode.rpm:
        return _install_rpm_deps(tempdir, config)
    raise ValueError(f'unexpected deps mode: {deps.mode}')


def _install_pip_deps(tempdir, config):
    """Install dependencies with pip."""
    log.info("Installing dependencies using pip")

    executable = sys.executable
    venv = config.pip_venv
    has_venv = _has_python_venv(sys.executable) if venv.enabled else False
    venv = None
    if venv == PipEnv.required and not has_venv:
        raise RuntimeError('venv (virtual environment) module not found')
    if has_venv:
        log.info('Attempting to create a virtualenv')
        venv = tempdir / "_venv_"
        _run([sys.executable, '-m', 'venv', str(venv)])
        executable = str(venv / "bin" / pathlib.Path(executable).name)
        # try to upgrade pip in the virtualenv. if it fails ignore the error
        _run([executable, '-m', 'pip', 'install', '-U', 'pip'])
    else:
        log.info('Continuing without a virtualenv...')
    if not _has_python_pip(executable):
        raise RuntimeError('pip module not found')

    # best effort to disable compilers, packages in the zipapp
    # must be pure python.
    env = os.environ.copy()
    env['CC'] = '/bin/false'
    env['CXX'] = '/bin/false'
    env['LC_ALL'] = 'C.UTF-8'  # work around some env issues with pip
    if env.get('PYTHONPATH'):
        env['PYTHONPATH'] = env['PYTHONPATH'] + f':{tempdir}'
    else:
        env['PYTHONPATH'] = f'{tempdir}'
    if config.pip_split:
        # a list of single item lists; so that pip run once for each
        # requirement
        req_batches = [[r] for r in config.requirements]
    else:
        # a list containing another list of the requirements, so we only
        # need to run pip once
        req_batches = [list(config.requirements)]
    for batch in req_batches:
        _run(
            [
                executable,
                "-m",
                "pip",
                "install",
                "--no-binary",
                ":all:",
                "--target",
                tempdir,
            ]
            + batch,
            env=env,
            check=True,
        )

    dinfo = DependencyInfo(config)
    res = _run(
        [executable, '-m', 'pip', 'list', '--format=json', '--path', tempdir],
        check=True,
        stdout=subprocess.PIPE,
    )
    pkgs = json.loads(res.stdout)
    for pkg in pkgs:
        dinfo.add(
            pkg['name'],
            version=pkg['version'],
            package_source='pip',
        )

    if venv:
        shutil.rmtree(venv)
    return dinfo


def _has_python_venv(executable):
    res = _run(
        [executable, '-m', 'venv', '--help'], stdout=subprocess.DEVNULL
    )
    return res.returncode == 0


def _has_python_pip(executable):
    res = _run(
        [executable, '-m', 'venv', '--help'], stdout=subprocess.DEVNULL
    )
    return res.returncode == 0


def _install_rpm_deps(tempdir, config):
    log.info("Installing dependencies using RPMs")
    dinfo = DependencyInfo(config)
    for pkg in config.requirements:
        log.info(f"Looking for rpm package for: {pkg!r}")
        _deps_from_rpm(tempdir, config, dinfo, pkg)
    return dinfo


def _deps_from_rpm(tempdir, config, dinfo, pkg):
    # first, figure out what rpm provides a particular python lib
    dist = f'python3dist({pkg})'.lower()
    try:
        res = subprocess.run(
            ['rpm', '-q', '--whatprovides', dist],
            check=True,
            stdout=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as err:
        log.error(f"Command failed: {err.args[1]!r}")
        log.error(f"An installed RPM package for {pkg} was not found")
        sys.exit(1)
    rpmname = res.stdout.strip().decode('utf8')
    # get version information about said rpm
    res = subprocess.run(
        ['rpm', '-q', '--qf', '%{version} %{release} %{epoch}\\n', rpmname],
        check=True,
        stdout=subprocess.PIPE,
    )
    vers = res.stdout.decode('utf8').splitlines()[0].split()
    log.info(f"RPM Package: {rpmname} ({vers})")
    dinfo.add(
        pkg,
        rpm_name=rpmname,
        version=vers[0],
        rpm_release=vers[1],
        rpm_epoch=vers[2],
        package_source='rpm',
    )
    # get the list of files provided by the rpm
    res = subprocess.run(
        ['rpm', '-ql', rpmname], check=True, stdout=subprocess.PIPE
    )
    paths = [l.decode('utf8') for l in res.stdout.splitlines()]
    # the top_level.txt file can be used to determine where the python packages
    # actually are. We need all of those and the meta-data dir (parent of
    # top_level.txt) to be included in our zipapp
    top_level = None
    for path in paths:
        if path.endswith('top_level.txt'):
            top_level = pathlib.Path(path)
    if not top_level:
        raise ValueError('top_level not found')
    meta_dir = top_level.parent
    pkg_dirs = [
        top_level.parent.parent / p
        for p in top_level.read_text().splitlines()
    ]
    meta_dest = tempdir / meta_dir.name
    log.info(f"Copying {meta_dir} to {meta_dest}")
    # copy the meta data directory
    shutil.copytree(meta_dir, meta_dest, ignore=_ignore_cephadmlib)
    # copy all the package directories
    for pkg_dir in pkg_dirs:
        pkg_dest = tempdir / pkg_dir.name
        log.info(f"Copying {pkg_dir} to {pkg_dest}")
        shutil.copytree(pkg_dir, pkg_dest, ignore=_ignore_cephadmlib)


def generate_version_file(versioning_vars, dest):
    log.info("Generating version file")
    log.debug("versioning_vars=%r", versioning_vars)
    with open(dest, "w") as fh:
        print("# GENERATED FILE -- do not edit", file=fh)
        for key, value in versioning_vars:
            print(f"{key} = {value!r}", file=fh)


def version_kv_pair(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError(f"not a key=value pair: {value!r}")
    key, value = value.split("=", 1)
    if key not in _VALID_VERS_VARS:
        raise argparse.ArgumentTypeError(f"Unexpected key: {key!r}")
    return key, value


def main():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("cephadm/build.py: %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

    log.debug("argv: %r", sys.argv)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "dest", help="Destination path name for new cephadm binary"
    )
    parser.add_argument(
        "--source", help="Directory containing cephadm sources"
    )
    parser.add_argument(
        "--python", help="The path to the desired version of python"
    )
    parser.add_argument(
        "--set-version-var",
        "-S",
        type=version_kv_pair,
        dest="version_vars",
        action="append",
        help="Set a key=value pair in the generated version info file",
    )
    parser.add_argument(
        '--pip-use-venv',
        choices=[e.name for e in PipEnv],
        default=PipEnv.auto.name,
        help='Configure pip to use a virtual environment when bundling dependencies',
    )
    parser.add_argument(
        "--bundled-dependencies",
        "-B",
        choices=[e.name for e in DependencyMode],
        default=DependencyMode.pip.name,
        help="Source for bundled dependencies",
    )
    args = parser.parse_args()

    if not _did_rexec() and args.python:
        _reexec(args.python)

    log.info(
        "Python Version: {v.major}.{v.minor}.{v.micro}".format(
            v=sys.version_info
        )
    )
    for argkey, argval in vars(args).items():
        log.info("Argument: %s=%r", argkey, argval)
    if not HAS_ZIPAPP:
        # Unconditionally display an error that the version of python
        # lacks zipapp (probably too old).
        print("error: zipapp module not found", file=sys.stderr)
        print(
            "(zipapp is available in Python 3.5 or later."
            " are you using a new enough version?)",
            file=sys.stderr,
        )
        sys.exit(2)
    if args.source:
        source = pathlib.Path(args.source).absolute()
    else:
        source = pathlib.Path(__file__).absolute().parent
    dest = pathlib.Path(args.dest).absolute()
    log.info("Source Dir: %s", source)
    log.info("Destination Path: %s", dest)
    _build(dest, source, Config(args))


if __name__ == "__main__":
    main()
