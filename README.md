# log-parse-agent

log-parse-agent is a golang program which runs in a Linux OS and allows grep and tail of local log files remotely via exposed API endpoints.

## Description

What application and log files to suppport is configured in the config file ./config/agent-config.json. 

The agent also supports sharing this configuration periodically to a central server so that the central server knows what log files to request for grep and tail operations.

## Getting Started

### Dependencies

You would need golang 1.20 or above to build and run this program.

### Clone the project

```
$ git clone https://github.com/mchopker/log-parse-agent
$ cd log-parse-agent
```

### Build and Run

```
$ go build
$ chmod 755 log-parse-agent
$ ./log-parse-agent
```

### Usage

The log-parse-agent program reads it config file ./config/agent-config.json on startup and allows grep and tail operations on the logs files configured via the API endpoints exposed. 

The following is the default configuration exist in the ./config/agent-config.json file:

```json

{
    "agent-host": "127.0.0.1",
    "agent-port": "9998",
    "server-url":"",
    "agent-info-post-interval-minutes": 30,
    "no-of-concurrent-req-allowed":2,
    "apps-supported": [
        {
	    "app": "TEST-APP-1",
            "search-timeout-minute": 1,
            "pre-match-lines-max": 9,
            "post-match-lines-max": 9,
            "logs": [
                "./log-samples/apache-access.log",
                "./log-samples/sample-2023-*.log"
            ],
            "active": true
        },
        {
            "app": "TEST-APP-2",
            "search-timeout-minute": 1,
            "pre-match-lines-max": 5,
            "post-match-lines-max": 5,
            "logs": [
                "./log-samples/sample-2023-01-01.log"
            ],
            "active": true
        }
    ]
}

```

The following are the explanation of the various attributes allowed in the  ./config/agent-config.json file:

| Attribute                               | Mandatory / Optional | Purpose                                                                                                                                                                                                                                                                                                            |
| :-------------------------------------- | :------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| agent-host                              | Mandatory            | The IPAddress of the agent machine where the API endpoints will be running. The default value is 127.0.0.1, change it to real IP if you want APIs to be called remotely.                                                                                                                                           |
| agent-port                              | Mandatory            | The port where Agent will expose it's endpoints.                                                                                                                                                                                                                                                                   |
| server-url                              | Optional             | The server url where the agent configuration will be posted periodically. Not needed if you do not want any central server/UI to become the client for this agent.                                                                                                                                                 |
| agent-info-post-interval-minutes        | Optional             | This is used only when the "server-url" attribute is not blank. The internal in minutes at which Agent will post it's configuration to central server, the defautl value is 30 minutes.                                                                                                                            |
| no-of-concurrent-req-allowed            | Mandatory            | The no. of concurrent API requests allowed by the agent.                                                                                                                                                                                                                                                           |
| apps-supported -> app                   | Mandatory            | The logical name you would want to give to a group of logs files you want this agent to be supported for remote grep/tail operations.                                                                                                                                                                              |
| apps-supported -> search-timeout-minute | Mandatory            | The timeout interval by which the grep / tail operations would automtically end if not completed early.                                                                                                                                                                                                            |
| apps-supported -> pre-match-lines-max   | Mandatory            | The max no. of lines before grep match allowed by this agent while sending request for grep via API endpoint.                                                                                                                                                                                                      |
| apps-supported -> post-match-lines-max  | Mandatory            | The max no. of lines after grep match allowed by this agent while sending request for grep via API endpoint.                                                                                                                                                                                                       |
| apps-supported -> logs                  | Mandatory            | The log files supported by this agent for grep / tail operations. It could be a relative or absolute path. It could contain a pattern match like '*' or '?' for which the Agent would support the latest file found for it. After the Agent starts you could see it via calling API endpoint /api/logs/search/info |
| apps-supported -> active                | Mandatory            | If the app and logs configured is enabled for the support by this agent.                                                                                                                                                                                                                                           |



### Testing

With the default configuration file (./config/agent-config.json) and sample logs provided (under ./log-samples/), once you start the log-parse-agent program, you can use curl or any other HTTP client to test various API endpoints.

The following are some API endpoints calls and outputs you would see:


An API call to check agent configuration loaded by agent:
```
$ curl -X GET http://127.0.0.1:9998/api/logs/search/info
{"server-url":"","no-of-concurrent-req-allowed":2,"agent-host":"127.0.0.1","agent-port":"9998","agent-info-post-interval-minutes":30,"apps-supported":[{"app":"TEST-APP-1","search-timeout-minute":1,"pre-match-lines-max":9,"post-match-lines-max":9,"logs":["./log-samples/apache-access.log","./log-samples/sample-2023-01-01.log"],"active":true},{"app":"TEST-APP-2","search-timeout-minute":1,"pre-match-lines-max":5,"post-match-lines-max":5,"logs":["./log-samples/sample-2023-01-01.log"],"active":true}]}
```

An API call to get list of log files where given search text match is found:
```
$ curl -X POST http://127.0.0.1:9998/api/logs/search/files -H "Content-Type: multipart/form-data" -F 'search-app=TEST-APP-1' -F 'search-files=./log-samples/apache-access.log' -F 'search-text=SAMSUNGGT'
{"data":["./log-samples/apache-access.log"]}
```

An API call to get list of log files where given search text match with regular expression is found:
```
$ curl -X POST http://127.0.0.1:9998/api/logs/search/files -H "Content-Type: multipart/form-data" -F 'search-app=TEST-APP-1' -F 'search-files=./log-samples/apache-access.log' -F 'search-text=SAMSUNG*' -F 'is-reg-ex=true'
{"data":["./log-samples/apache-access.log"]}
```

An API call to get log lines where the given serach text match is found (note the first line of output would be a key string used to issue the cancel operation later):
```
$ curl -X POST http://127.0.0.1:9998/api/logs/search/lines -H "Content-Type: multipart/form-data" -F 'search-app=TEST-APP-1' -F 'search-files=./log-samples/apache-access.log' -F 'search-text=SAMSUNGGT' -F 'pre-match-lines=0' -F 'post-match-lines=0'
grep-l./log-samples/apache-access.log
45.153.227.31 - - [19/Dec/2020:17:44:54 +0100] "GET /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 9873 "-" "Mozilla/5.0(Linux;Android5.0.1;SAMSUNGGT-I9505)AppleWebKit/537.36(KHTML,likeGecko)SamsungBrowser/12.1Chrome/79.0.3945.136MobileSafari/537.36" "-"
45.153.227.31 - - [19/Dec/2020:17:44:54 +0100] "POST /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 188 "-" "Mozilla/5.0(Linux;Android5.0.1;SAMSUNGGT-I9505)AppleWebKit/537.36(KHTML,likeGecko)SamsungBrowser/12.1Chrome/79.0.3945.136MobileSafari/537.36" "-"
```

An API call to tail a given log file (note the first line of output would be a key string used to issue the cancel operation later):
```
$ curl -X POST http://127.0.0.1:9998/api/logs/tail/files -H "Content-Type: multipart/form-data" -F 'search-app=TEST-APP-1' -F 'search-file=./log-samples/apache-access.log'
tail./log-samples/apache-access.log
176.222.58.254 - - [19/Dec/2020:17:41:51 +0100] "POST /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 188 "-" "Mozilla/5.0(Macintosh;IntelMacOSX10_7_5)AppleWebKit/537.36(KHTML,likeGecko)Chrome/49.0.2623.112Safari/537.36" "-"
45.132.51.62 - - [19/Dec/2020:17:42:43 +0100] "GET /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 9873 "-" "Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/83.0.4103.116Safari/537.36" "-"
45.132.51.62 - - [19/Dec/2020:17:42:44 +0100] "POST /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 188 "-" "Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/83.0.4103.116Safari/537.36" "-"
45.153.227.31 - - [19/Dec/2020:17:44:54 +0100] "GET /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 9873 "-" "Mozilla/5.0(Linux;Android5.0.1;SAMSUNGGT-I9505)AppleWebKit/537.36(KHTML,likeGecko)SamsungBrowser/12.1Chrome/79.0.3945.136MobileSafari/537.36" "-"
45.153.227.31 - - [19/Dec/2020:17:44:54 +0100] "POST /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 188 "-" "Mozilla/5.0(Linux;Android5.0.1;SAMSUNGGT-I9505)AppleWebKit/537.36(KHTML,likeGecko)SamsungBrowser/12.1Chrome/79.0.3945.136MobileSafari/537.36" "-"
45.144.0.179 - - [19/Dec/2020:17:45:02 +0100] "GET /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 9873 "-" "Mozilla/5.0(Linux;Android7.0;G3311Build/43.0.A.7.106;wv)AppleWebKit/537.36(KHTML,likeGecko)Version/4.0Chrome/85.0.4183.81MobileSafari/537.36EdgW/1.0" "-"
45.144.0.179 - - [19/Dec/2020:17:45:03 +0100] "POST /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 188 "-" "Mozilla/5.0(Linux;Android7.0;G3311Build/43.0.A.7.106;wv)AppleWebKit/537.36(KHTML,likeGecko)Version/4.0Chrome/85.0.4183.81MobileSafari/537.36EdgW/1.0" "-"
176.222.58.254 - - [19/Dec/2020:17:46:28 +0100] "GET /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 9873 "-" "Mozilla/5.0(Linux;Android10;Nokia7plus)AppleWebKit/537.36(KHTML,likeGecko)Chrome/84.0.4147.111MobileSafari/537.36" "-"
176.222.58.254 - - [19/Dec/2020:17:46:29 +0100] "POST /index.php?option=com_contact&view=contact&id=1 HTTP/1.1" 200 188 "-" "Mozilla/5.0(Linux;Android10;Nokia7plus)AppleWebKit/537.36(KHTML,likeGecko)Chrome/84.0.4147.111MobileSafari/537.36" "-"
```

An API call to cancel the tail operation triggered via previous tail API call (note the input is the key string which was received as part of tail operation earlier):
```
$ curl -X POST http://127.0.0.1:9998/api/logs/command/cancel -H "Content-Type: multipart/form-data" -F 'cmd-key=tail./log-samples/apache-access.log'
```



## Authors

Mahesh Kumar Chopker - mchopker@gmail.com

## Version History

* 0.1
    * Initial Release

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)

