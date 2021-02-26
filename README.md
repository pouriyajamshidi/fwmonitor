# IPTABLES/UFW Monitor

fwmonitor is a Python script that can be used to display ```iptables``` or ```UFW``` logs from your ```syslog``` or a text ```file``` in a nice and easy to understand format in order to conduct network traffic analysis.

## Demo

[![asciicast](https://asciinema.org/a/394593.svg)](https://asciinema.org/a/394593)

## Usage

For your convenience, you can place the program in your system PATH, like /bin/ or /usr/bin/ . For instance:

```bash
cp fwmonitor.py /bin/fwmonitor && chmod +x /bin/fwmonitor
```

If you prefer to run it where it has been cloned, make it execuatable by running:

```bash
chmod +x fwmonitor.py
```

This script takes 3 optional arguments. The arguments are:

```-file```   # default is /var/log/syslog

```-key```    # default is "UFW BLOCK" -- make sure of case-sensitivity

```-interval```   # default is 60 seconds

By running it without providing any arguments, default values will be used.

```python
./fwmonitor.py
```

OR

```python
python3 fwmonitor.py
```

OR

To analyze a log file that you have gathered:

```python
python3 fwmonitor.py -file mytraffic.log -key "IPTABLES_BLOCK" -interval onetime
```

By providing ```onetime``` keyword argument to ```-interval``` switch you are asking the program to exit after scanning the log file once.

Another example of its use on a live server:

```python
python3 fwmonitor.py -file /var/log/syslog -key "IPTABLES_BLOCK"
```

## Tested on

Ubuntu and Debian machines.

It can be used on ```Windows``` as well but just to analyze the already gathered log files.

## Contributing

Pull requests are welcome.

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
