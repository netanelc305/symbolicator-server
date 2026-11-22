# symbolicator-server

A symbol server for Apple crash reports. It scans IPSWs into a SQLite database of symbols once, then
symbolicates `.ips` reports (panics, stackshots, crashes) against it, for any device and build it holds.

## Requirements

- Python 3.9 - 3.14
- On the machine that runs the server:
  - [`ipsw`](https://github.com/blacktop/ipsw), which extracts the symbols from IPSWs:

    ```shell
    brew install blacktop/tap/ipsw
    ```

  - The kernel signatures from [blacktop/symbolicator](https://github.com/blacktop/symbolicator), which `ipsw`
    uses to name the functions of the stripped kernel and kexts:

    ```shell
    git clone https://github.com/blacktop/symbolicator.git
    ```

## Install

```shell
python3 -m pip install -U symbolicator-server
```

or

```shell
uv tool install symbolicator-server
```

This installs the client only (`scan`, `symbolicate`, `stats`, `version`). On the machine that runs the
server, install the `server` extra:

```shell
python3 -m pip install -U "symbolicator-server[server]"
```

## Usage

### Run the server

```shell
symbolicator serve syms.db /PATH/TO/symbolicator/kernel
```

- `syms.db` is the database the symbols are kept in. It is created if it does not exist; `--override-db`
  replaces an existing one with a new, empty database.
- `/PATH/TO/symbolicator/kernel` is the `kernel` folder of the `symbolicator` repository you cloned.
- `--host` and `--port` (default `localhost:3993`) set where it listens; `-v` logs every name a scan adds or keeps.

### Scan an IPSW

```shell
symbolicator scan iPhone17,1_18.2_22C152_Restore.ipsw

✓ 0:00:42 Uploaded: 8.1 / 8.1 GB
⠏ 0:01:22 Loaded: 2,200 images, 4,113,810 symbols
```

An IPSW that is already loaded is refused; `--force` loads it again.

### Symbolicate a report

```shell
symbolicator symbolicate stacks-2026-09-25-201009.ips -p thermalmonitord
```

```
[25Sep2026 20:10:09] - Stackshot - iPhone13,4 iPhone OS 26.5.2 (23F84)
Reason: stackshot via sysdiagnose
...
Process: thermalmonitord [66]
  Thread: 1655
    State:          TH_WAIT
    Base Priority:  37
    Sched Priority: 37
    User Time:      1937232 usec
    System Time:    3069104 usec
    User Frames:
      00: libsystem_kernel.dylib  0x2322c1cd4  _mach_msg2_trap + 8
      01: libsystem_kernel.dylib  0x2322c522c  _mach_msg_overwrite + 424
      02: libsystem_kernel.dylib  0x2322c5078  _mach_msg + 24
      03: CoreFoundation          0x18354a344  ___CFRunLoopServiceMachPort + 160
      ...
```

By default only the panicked process is shown (every process for reports without one). `-p NAME` shows one
process, `-a` all of them, and `--json` prints the server's JSON instead.

### Database stats

```shell
symbolicator stats        # size and rows per table
symbolicator stats -v     # and the loaded IPSWs
```

The client commands talk to `http://localhost:3993` by default; set `-s URL` or `SYMBOLICATOR_SERVER` for
another server.
