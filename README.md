# scavenger
scavenger :  is a multi-threaded post-exploitation scanning tool for scavenging systems, finding most frequently used files and folders as well as "interesting" files containing sensitive information. 

## Problem Definition:
Scavenger confronts a challenging issue typically faced by Penetration Testing consultants during internal penetration tests; the issue of having too much access to too many systems with limited days for testing.

### Requirements:

* Install CrackMapExec -
[CrackMapExec Installation Page](https://github.com/byt3bl33d3r/CrackMapExec/wiki/Installation)

### Examples:

```
$ python3 ./scavenger.py smb -t 10.0.0.10 -u administrator -p Password123 -d test.local
```

```
$ python3 ./scavenger.py smb --target iplist --username administrator --password Password123 --domain test.local --overwrite
```

## Blog Post:

[Link to Trustwave SpiderLabs Blog](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/scavenger-post-exploitation-tool-for-collecting-vital-data/)

## Acknowledgements - Powered and Inspired by:

* [Impacket](https://github.com/CoreSecurity/impacket) (@agsolino)
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (@byt3bl33d3r)
* [ccsrch](https://github.com/adamcaudill/ccsrch) (@adamcaudill)
* [LaZagne](https://github.com/AlessandroZ/LaZagne)

## Notice:

The "ssh" capability of scavenger has not been uploaded to GitHub yet, there is a change I have to make, and in the interest of not delaying to upload as a whole, I have decided to remove the ssh functionality for the moment. 

The "ssh" capability will be re-added soon.

Thank you for your patience

./haxrbyte