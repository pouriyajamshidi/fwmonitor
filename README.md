# fwmonitor/IPTABLES Analyzer

fwmonitor is a Python script that can be used to display ```iptables``` or ```UFW``` logs from your ```syslog``` or a log/text file in a nice and easy to understand format in order to conduct network traffic analysis and security audit.

## Demo

[![asciicast](https://asciinema.org/a/394593.svg)](https://asciinema.org/a/394593)

## Usage

Make the script execuatable:

```bash
chmod +x fwmonitor.py
```

For your convenience, you can place the program in your system PATH, like ```/bin/``` or ```/usr/bin/``` for instance:

```bash
sudo cp fwmonitor.py /bin/fwmonitor
```

This script takes 3 optional arguments. The arguments are:

**```-file```**   # location of log file to be scanned. *Default is /var/log/syslog*

**```-key```**    # keyword that ```IPTABLES``` uses to log events. Make sure of case-sensitivity and specific keyword in your log file. *Default is "UFW BLOCK"*

**```-interval```**   # Interval to read the log file from scratch, this is useful for analyzing a live system. If you pass ```onetime``` here, it'll scan the log file once and exits. *Default is 60 seconds.*.

*By running the script without providing any arguments, default values will be used.*

```python
./fwmonitor.py
```

OR

```python
python3 fwmonitor.py
```

## Examples

To analyze a log file that you have gathered:

```python
python3 fwmonitor.py -file mytraffic.log -key "IPTABLES_BLOCK" -interval onetime
```

As mentioned earlier, by providing ```onetime``` keyword argument to ```-interval``` switch you are asking the program to exit after scanning the log file once.

Audit a live server:

```python
python3 fwmonitor.py -file /var/log/syslog -key "IPTABLES_BLOCK"
```

## Tested on

Ubuntu and Debian machines.

It can be used on ```Windows``` and ```Mac OS``` as well to analyze the already gathered log file(s).

## Contributing

Pull requests are welcome.

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
