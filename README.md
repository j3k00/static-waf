Static WAF with ModSecurity
==========================
This guide will give you some tips for installing a "static" Modsecurity (an open-source web application firewall - WAF) in a self-contained mode (it means that  the action of the first rule that matches is taken and the rest of the rules are not checked in most of the cases). Note that this approach detects a lot of false positives and should be improved using the Anomaly Scoring Mode.
#### Platform tested
##### SUSE Linux Enterprise Server
OS used can be downloaded here: [SUSE Linux Enterprise Server 12 SP4 x86-64](https://www.suse.com/products/server/downloadab/gykG3yRL7Tk~/?event_id=GSDGNtria34126&event_name=Eval:+SLES+12+SP4+x86-64&icid=GSDGNtria34127&icname=Eval:+SLES+12+SP4+x86-64+Nuture&build=gykG3yRL7Tk~)

Type | Value
---|---
Kernel Name   |  Linux 
Kernel Release|  4.12.14-94.41-default 
Hardware Architecture |  x86_64
OS information |  GNU/Linux 
OS Distribution version| SUSE Linux Enterprise Server 12 SP4
OS Release version | 12.4 
Python version | 3.6.5
GCC version | 7.3.1

##### Ubuntu Server
OS used can be downloaded here: [Ubuntu Server 18.04.3 LTS](https://ubuntu.com/download/server)

Type | Value
---|---
Kernel name | Linux
Kernel Release | 4.15.0-70-generic
Hardware Architecture | x86_64
OS information | GNU/Linux
OS Distribution version | Ubuntu Server 18.04.3 LTS
OS Release version | 18.04.3
Python version | 3.6.9
GCC version | 7.4.0

## Setup the environment
In the following paragraphs there are all the instructions to setup the environment:
1. Download and install OS
2. Install Modsecurity
3. Set the OWASP CRS
### 1. Download and install OS
##### SUSE Linux
Download and install the openSUSE15.0 repository from [here](https://software.opensuse.org/download/package?package=python3&project=openSUSE%3ALeap%3A15.0). 
Add the following packages:
```sh
$ sudo zypper addrepo http://download.opensuse.org/repositories/devel:libraries:c_c++/SLE_12_SP1/devel:libraries:c_c++.repo
$ sudo zypper addrepo http://download.opensuse.org/repositories/devel:tools:building/SLE_12_SP1/devel:tools:building.repo
$ sudo zypper ar http://download.opensuse.org/repositories/systemsmanagement/SLE_12_SP2/systemsmanagement.repo
$ sudo zypper addrepo http://download.opensuse.org/repositories/Education/SLE_12/Education.repo
$ sudo zypper addrepo http://download.opensuse.org/repositories/multimedia:libs/SLE_12_SP2/multimedia:libs.repo
$ sudo zypper refresh
$ sudo zypper in gcc7-c++ 
$ sudo zypper in gcc-c++ 
$ sudo zypper in git-core
$ sudo zypper in pcre-devel
$ sudo zypper in flex bison curl libjal2 libtool libxml2-2
```
##### On Ubuntu
Add the following packages:
```sh
$ sudo apt-get install flex
$ sudo apt-get install bison
$ sudo apt-get install curl
$ sudo apt-get install libtool
$ sudo apt-get install libyajl-dev
$ sudo apt-get install libxml
$ sudo apt-get install libpcre3-dev
$ sudo apt install python3-pip
```
### 2. Install ModSecurity
These steps come from [ModSecurity Releases](https://github.com/SpiderLabs/ModSecurity/releases) and [ModSecurity Installation Guide](https://github.com/SpiderLabs/ModSecurity/wiki) with some adjustments.

``` sh
$ cd /opt/
$ sudo wget https://github.com/SpiderLabs/ModSecurity/releases/download/v3.0.3/modsecurity-v3.0.3.tar.gz
$ sudo tar -xvzf modsecurity-v3.0.3.tar.gz
$ sudo mv modsecurity-v3.0.3 ModSecurity
$ cd ModSecurity/
$ export MODSECURITY_INC="/usr/local/modsecurity/include"
$ export MODSECURITY_LIB="/usr/local/modsecurity/lib"
$ sudo ./configure --prefix=/usr/local
$ sudo make
$ sudo make install
```

These steps come from [pymodsecurity](https://github.com/actions-security/pymodsecurity) with some adjustments. Remember to execute the following commands in ModSecurity folder (`/opt/ModSecurity/`).

```sh
$ git clone --recurse-submodules https://github.com/actions-security/pymodsecurity.git
$ cd pymodsecurity
$ sudo git checkout -b v0.0.4
$ sudo pip3 install pybind11
$ sudo pthon3 setup.py install
```

### 3. OWASP ModSecurity Core Rule Set (CRS)

These steps come from [OWASP ModSecurity. CRS](https://modsecurity.org/crs/#:~:targetText=The%20OWASP%20ModSecurity%20Core%20Rule,a%20minimum%20of%20false%20alerts.). Remember to execute the following command in pymodsecurity folder (`/opt/ModSecurity/pymodsecurity/`).
```sh
$ sudo git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git
```
# Main 
The `waf.py` program (copy it into `/opt/ModSecurity/pymodsecurity/examples/`) accept an input file and return a csv file with the additional field **ModSecFlag** settet to 1 (true) if a rule is triggered, otherwise it is set to 0 (false).

The input text file was based on [Cloudflare Log](https://developers.cloudflare.com/logs/about/) dropped with some attributes.
```json
{
    "ClientCountry":"us",
    "ClientDeviceType":"mobile",
    "ClientIP":"23.56.175.55",
    "ClientIPClass":"noRecord",
    "ClientRequestHost":"www.xyz.org",
    "ClientRequestMethod":"GET",
    "ClientRequestURI":"/test?key1=value1&key2=value2&key3=value3&test=args&test=test",
    "ClientRequestUserAgent":"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
}
```
#### Rules
There are no security rules configured by default, so we need to enable the rules. Edit the `basic_rules.conf` file (located at `/opt/ModSecurity/pymodsecurity/examples/`)  and set the ‘SecRuleEngine’ option to **On**:
```
SecRuleEngine On
```
The `modsec_rules.conf` files (in `/opt/ModSecurity/pymodsecurity/modsec_rules.conf`) contains all the rules to include.
```
include examples/basic_rules.conf
include owasp-modsecurity-crs/crs-setup.conf
include owasp-modsecurity-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
include owasp-modsecurity-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
include owasp-modsecurity-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
include owasp-modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
include owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
include owasp-modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
include owasp-modsecurity-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
```

These rules (located in `/opt/ModSecurity/pymodsecurity/owasp-modsecurity-crs/rules/`) are set to **"block"** as default. For setting WAF in self-contained mode, replacing **"block"** with **"deny"**.

```sh
$ cd /opt/ModSecurity/pymodsecurity/owasp-modsecurity-crs
$ sudo cp crs-setup.conf.example crs-setup.conf
$ cd rules
$ sudo sed -i 's/block/deny/' REQUEST-930-APPLICATION-ATTACK-LFI.conf
$ sudo sed -i 's/block/deny/' REQUEST-931-APPLICATION-ATTACK-RFI.conf
$ sudo sed -i 's/block/deny/' REQUEST-932-APPLICATION-ATTACK-RCE.conf
$ sudo sed -i 's/block/deny/' REQUEST-933-APPLICATION-ATTACK-PHP.conf
$ sudo sed -i 's/block/deny/' REQUEST-941-APPLICATION-ATTACK-XSS.conf
$ sudo sed -i 's/block/deny/' REQUEST-942-APPLICATION-ATTACK-SQLI.conf
$ sudo sed -i 's/block/deny/' REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
```

### Enjoy
Link to the unicode.mapping file
```sh
$ sudo ln -s /opt/ModSecurity/unicode.mapping /opt/ModSecurity/pymodsecurity/examples/
```
Now, you can run the program.
```sh
$ sudo python3 waf.py -i log.txt - o result.csv
```
