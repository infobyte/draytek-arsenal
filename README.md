# Draytek Arsenal: Observability and hardening toolset for Draytek edge devices.
Advanced attackers are increasingly choosing edge devices as targets. However, these devices are controlled by closed-source software known as firmware, often distributed in a proprietary format. This is an added difficulty for defenders and researchers, who must understand how to extract firmware to assess its security.

This is more than just a hypothetical scenario, as we discovered recently when a client was compromised. With Draytek equipment at the edge of their infrastructure, the natural question was: Could this be the attackers' entry point? Over 500k Draytek devices are exposed to the Internet. Yet, no working tool exists to extract their firmware and assist researchers and defenders working with these devices.

During our assessment, we reverse-engineered Draytek's firmware format, which contains a bootloader, a compressed RTOS kernel, and two filesystems. Through our investigation, we developed tools to extract these components, unveiling the real-time operating system's capability to load code modules dynamically. These modules are loaded from one of the filesystems in the firmware image during boot but can also be loaded while the system is running and stored in a separate filesystem in flash memory. An attacker can exploit this feature to achieve persistence by loading a module that remains active even after a reboot or firmware upgrade, and the end-user does not have a way to detect this type of attack. Consequently, we developed our own module to check the integrity of loaded modules in memory, mitigating this potential threat.

In our pursuit of a more secure internet, we are making this set of tools accessible to the community, enabling observability, hardening, transparency, and vulnerability research on Draytek edge devices

## Note
We initially developed this as a internal tool. Just as a set of scripts but showed great potential, prompting us to make it open source. Since then, we are working to integrate these scripts into the python package you will find in this repo, and to make them compatible with other device models.

## Get started ##

__Requirements:__

* Python3
* Docker (Optional)

### Installation ###

(Optional) Create and activate python virtual environment:
```bash
$ python3 -m virtualenv .venv
$ source .venv/bin.activate
```

Install `draytek_arsenal`:
```bash
$ cd draytek_arsenal
$ python3 -m pip install -r requirements.txt
$ python3 -m pip install .
```

Test the installation:
```
$ python3 -m draytek_arsenal
```

### Install as developer ###

This installation will be affected by local code changes
```
$ python3 -m pip install -e .
```

### Mips-tools ###

Some commands as `mips_compile` and `mips_merge` needs a complementary Docker image in order to work.  
If it has not been downloaded this error message is shown:
```
[x] Image 'draytek-arsenal' not found. Please build or download the image.
```

You could download the image with the following command:

```bash
$ docker pull ghcr.io/infobyte/draytek-arsenal:main
```

Or build it with:
```bash
$ docker build -t draytek-arsenal ./mips-tools
```


## Usage ##

`draytek-arsenal` is a set of scripts collected in a python package. So, to use it you should select a command:

```
usage: draytek-arsenal [-h] [command] args..
```

Some of the commands are:


### parse_firmware ###

Parse and show information of a Draytec firmware.

```
usage: parse_firmware [-h] firmware

positional arguments:
  firmware    Path to the firmware

options:
  -h, --help  show this help message and exit
```

### extract ###

Command used to extract and decompress Draytek packages.

```
usage: extract [-h] [--rtos RTOS] firmware

positional arguments:
  firmware              Path to the firmware

options:
  -h, --help            show this help message and exit
  --rtos RTOS, -r RTOS  Where to extract and decompress the RTOS
```

### dlm_hash ###

Get the hash of a DLM module.

```
usage: dlm_hash [-h] [-c] dlm

positional arguments:
  dlm         Path to the dlm

options:
  -h, --help  show this help message and exit
  -c          Print as .c code
```

### find_loading_addr ###

Find the address where the RTOS if loaded with the first jump instruction.

```
usage: find_loading_addr [-h] rtos

positional arguments:
  rtos        Path to the rtos

options:
  -h, --help  show this help message and exit
```

### find_endianness ###

Checks if the RTOS is little or big endian.

```
usage: find_endianness [-h] rtos

positional arguments:
  rtos        Path to the rtos

options:
  -h, --help  show this help message and exit
```

### mips_compile ###

Compile MIPS relocatable binary (used for DLMs).

```
usage: mips_compile [-h] output [input ...]

positional arguments:
  output      Output file
  input       Output file

options:
  -h, --help  show this help message and exit
```

### mips_merge ###

Merge two ELF MIPS relocatable files.

```
usage: mips_merge [-h] first_input second_input output

positional arguments:
  first_input   First input file
  second_input  Second input file
  output        Output file

options:
  -h, --help    show this help message and exit
```
