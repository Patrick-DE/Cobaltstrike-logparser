# Log-Parser for CobaltStrike

## Usage
Quick usage:
```
python3 gimmelogs.py -p ./ -o ./
```
Recommended usage:
```
python3 gimmelogs.py -w 16 -m -p ./ -o ./ -e exclude.txt
```
1. Download the CobaltStrike "logs" folder to disk and specify this folder as -p PATH.
2. For cleaner reports choose -m 
3. If you are testing your payloads exclude them via -e
4. Specify the -o PATH to generate the reports

## Commands
```
Parse CobaltStrike logs and store them in a DB to create reports

optional arguments:
  -h, --help                    show this help message and exit
  -w WORKER, --worker WORKER    Set amount of workers: default=10
  -v, --verbose                 Activate debugging
  -p PATH, --path PATH          Directory path to start from generating the DB
  -d DATABASE, --database DATABASE  Database path: default=./log.db
  -o OUTPUT, --output OUTPUT    Output path for CSV
  -m, --minimize                Remove unnecessary data: keyloggs,beaconbot,sleep,exit,clear
  -e EXCLUDE, --exclude EXCLUDE A file with one IP-Range per line which should be ignored
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

❌ Create cleaner download / upload report