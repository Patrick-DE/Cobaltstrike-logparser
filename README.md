# C2 Log-Parser
## Support for Cobalt Strike and Brute Ratel

## Usage
Quick usage:
```
python3 gimmelogs.py -l <LogDir>
```
Recommended usage:
```
python3 gimmelogs.py -l <LogDir> -c config.yml -m
```
1. Download the CobaltStrike "logs" folder to disk and specify this folder as -l logs.
2. For cleaner reports choose -m 
3. If you are testing your payloads exclude them via the config -c
4. Specify the -p PATH to generate the reports and DB into a custom folder

## Commands
```
Parse CobaltStrike logs and store them in a DB to create reports

optional arguments:
  -h, --help                    show this help message and exit
  -w WORKER, --worker WORKER    Set amount of workers: default=10
  -v, --verbose                 Activate debugging
  -l LOGS, --logs LOGS          Directory path to start crawling the logs
  -p PATH, --path PATH          Output path for the reports and DB
  -m, --minimize                Remove unnecessary data: keyloggs,beaconbot,sleep,exit,clear
  -c CONFIG, --config CONFIG    A config file, see config_template.yml
  -x PARSER, --parser           Select either "cs" (default) or "br"
```
## Reporting
* Report for input and tasks being issued via CobaltStrike
  * Contains INPUT (operator input) and TASK (cna + response from input)
* Report for downloaded and uploaded files
  * Contains download.log, INDICATOR (hash and filename) and entries containing the following keyphrases:
    * Uploading beaconloader:
    * Uploading payload file:
    * Tasked beacon to upload
  * Not really pretty right now 🤷‍♂️
* Report of the valid beacons. They have the following set:
  * Beacon.hostname
  * Beacon.joined


## Remarks
* Only beacons with input or tasks are being listed to allow the report to focus on actual actions instead of an complete picture. As a result, beacons which will just be spawned due to persistence and not be used will be ignored.
* <s>Beacons which have not been used (no metadata), thus listed under the unknown folder will be ignored</s>
* Beacons without associated IDs, usually happens from broken .cna scripts will be ignored

## Todos
✔ Make it work 😂
✔ No support for linux as of now :( 
❌ Create cleaner download / upload report
