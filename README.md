# `certificate_cli`

**Usage**:

```console
$ certificate_cli [OPTIONS] COMMAND [ARGS]...
```

**Options**:

* `--install-completion`: Install completion for the current shell.
* `--show-completion`: Show completion for the current shell, to copy it or customize the installation.
* `--help`: Show this message and exit.

**Commands**:

* `generate`: Generate a SSL certificate
* `info`: Basic info of a pem certificate
* `simulate`: Provide a path to public and private...

## `certificate_cli generate`

Generate a SSL certificate

**Usage**:

```console
$ certificate_cli generate [OPTIONS]
```

**Options**:

* `--days INTEGER`: [default: 30]
* `--prefix TEXT`
* `--path TEXT`: [default: ./certs]
* `--help`: Show this message and exit.

## `certificate_cli info`

Basic info of a pem certificate

**Usage**:

```console
$ certificate_cli info [OPTIONS] PATH
```

**Arguments**:

* `PATH`: [required]

**Options**:

* `--help`: Show this message and exit.

## `certificate_cli simulate`

Provide a path to public and private certificates.

Use --port to specify a port to serve the certificat on.

**Usage**:

```console
$ certificate_cli simulate [OPTIONS] PUBLIC PRIVATE
```

**Arguments**:

* `PUBLIC`: [required]
* `PRIVATE`: [required]

**Options**:

* `--port INTEGER`: [default: 5678]
* `--help`: Show this message and exit.

## Build

1. Increment versions in `__init.py__` and `pyproject.toml`
2. Update changelog (`git log --pretty=format:"%h - %s (%an, %ad)" --date=short` for starters, also see [git-chglog](https://github.com/git-chglog/git-chglog)).
3. `build` and `publish`

```
poetry build
poetry publish
or 
poetry publish --build