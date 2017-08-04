# amicontained

[![Travis CI](https://travis-ci.org/jessfraz/amicontained.svg?branch=master)](https://travis-ci.org/jessfraz/amicontained)

Container introspection tool. Find out what container runtime is being used as
well as features available.

## Installation

#### Binaries

- **linux** [386](https://github.com/jessfraz/amicontained/releases/download/v0.0.1/amicontained-linux-386) / [amd64](https://github.com/jessfraz/amicontained/releases/download/v0.0.1/amicontained-linux-amd64) / [arm](https://github.com/jessfraz/amicontained/releases/download/v0.0.1/amicontained-linux-arm) / [arm64](https://github.com/jessfraz/amicontained/releases/download/v0.0.1/amicontained-linux-arm64)

#### Via Go

```bash
$ go get github.com/jessfraz/amicontained
```

## Usage

```console
$ amicontained -h
                 _                 _        _                _
  __ _ _ __ ___ (_) ___ ___  _ __ | |_ __ _(_)_ __   ___  __| |
 / _` | '_ ` _ \| |/ __/ _ \| '_ \| __/ _` | | '_ \ / _ \/ _` |
| (_| | | | | | | | (_| (_) | | | | || (_| | | | | |  __/ (_| |
 \__,_|_| |_| |_|_|\___\___/|_| |_|\__\__,_|_|_| |_|\___|\__,_|
 Container introspection tool.
 Version: v0.0.1

  -d	run in debug mode
  -v	print version and exit (shorthand)
  -version
    	print version and exit
```

## Examples

**Docker**

```console
$ docker run --rm -it r.j3ss.co/amicontained
Container Runtime: docker
Host PID Namespace: false
AppArmor Profile: docker-default (enforce)
User Namespace: true
User Namespace Mappings:
	Container -> 0
	Host -> 886432
	Range -> 65536

$ docker run --rm -it --pid host r.j3ss.co/amicontained
Container Runtime: docker
Host PID Namespace: true
AppArmor Profile: docker-default (enforce)
User Namespace: false

$ docker run --rm -it --security-opt "apparmor=unconfined" r.j3ss.co/amicontained
Container Runtime: docker
Host PID Namespace: false
AppArmor Profile: unconfined
User Namespace: false
```

**unshare**

```console
$ sudo unshare --user -r
root@coreos:/home/jessie/.go/src/github.com/jessfraz/amicontained# ./amicontained
Container Runtime: not-found
Host PID Namespace: true
AppArmor Profile: unconfined
User Namespace: true
User Namespace Mappings:
	Container -> 0
	Host -> 0
	Range -> 1
```
