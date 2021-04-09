# sample-microsoft-windows-10-stig-overlay

Overlay for the baseline InSpec profile at https://github.com/mitre/microsoft-windows-10-stig-baseline with modifications based on provided requirements. The baseline InSpec profile is used validate the secure configuration of Microsoft Windows 10 against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Microsoft Windows 10 STIG.

## Getting Started  
It is intended and recommended that InSpec and this profile be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target [ remotely over __winrm__].

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

__The simplest way to install InSpec is to use this command for *nix or Mac:__
```
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P chef-workstation
```

__or this command for Windows (Powershell)__
```
. { iwr -useb https://omnitruck.chef.io/install.ps1 } | iex; install -project chef-workstation
```

Latest versions and other installation options are available at the [InSpec](http://inspec.io/) site.


## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
# Set flag to "true" if the target system is sensitive
sensitive_system: "false"

# List of authorized users in the Backup Operators group e.g. ["Joe", "Gina"]
backup_operators: []

# List of authorized users in the local Administrators group e.g. ["Joe", "Gina"]
administrators: []

# List of authorized users in the Hyper-V Group e.g. ["Joe", "Gina"]
hyper_v_admin: []

# This is a list of Approved Anti-Virus Software e.g. ["Windows Defender", "McAfee Host Intrusion Prevention", "McAfee Endpoint Security", "McAfee Agent"]
av_approved_software: []

```

## Running This Overlay Directly from Github

```
# How to run
inspec exec https://github.com/mitre/sample-microsoft-windows-10-stig-overlay/archive/main.tar.gz -t winrm://<user>@<host> --password <password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Overlay from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/sample-microsoft-windows-10-stig-overlay.git
inspec archive sample-microsoft-windows-10-stig-overlay
inspec exec <name of generated archive> -t winrm://<user>@<host> --password <password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd sample-microsoft-windows-10-stig-overlay
git pull
cd ..
inspec archive sample-microsoft-windows-10-stig-overlay --overwrite
inspec exec <name of generated archive> -t winrm://<user>@<host> --password <password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.



## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/sample-microsoft-windows-10-stig-overlay/issues/new).

### NOTICE 

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
