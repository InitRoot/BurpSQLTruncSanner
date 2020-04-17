#  [WIP]SQLTruncScanner - Scan endpoints for possible SQL Truncation vulnerabilities.
![Follow on Twitter](https://img.shields.io/twitter/follow/initroott?label=Follow%20&style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/initroot/BurpSQLTruncSanner)
![GitHub stars](https://img.shields.io/github/stars/initroot/BurpSQLTruncSanner)

Burp Extension for identifying possible SQL Truncation vulnerabilities. 
 - Fuzz each parameter within request
 - Adds padding up to 40 characters
 
Copyright (c) 2020 Frans Hendrik Botes (InitRoot)

##  Disclaimer
I take not responsibility for your use of the software. Development is done in my personal capacity and carry no affiliation to my work.

## Setup
For use with the professional version of Burp Suite, might work with the Community Edition. Ensure you have JPython loaded and setup before installing.

You can modify the payload padding list by updating the payloadSet parameter on line 268.

```
# Needed params

payloadSet = {"5": '     00', "10": '          00', "15": '               00', "20": '                    00', "30": '                              00', "40": '                                        00'}


```

## Usage

Once you have a request that you would like tested, right click and select the scanner from the context menu.
You can monitor the results on the Extender, Plugin, Output window. A issue will be raised if possible issue is detected.
The issue will outline the parameter and payload set found to be potentially vulnerable. This can then be manually confirmed by recreating the request in your Repeater.

Once the issue is fixed of the wrong HTTP Messages used for raising the issues, you would be able to just send the response to repeater.


##  Screenshot
![](https://raw.githubusercontent.com/InitRoot/BurpSQLTruncSanner/master/SQLTrunc1.png)
![](https://raw.githubusercontent.com/InitRoot/BurpSQLTruncSanner/master/SQLTrunc2.png)
![](https://raw.githubusercontent.com/InitRoot/BurpSQLTruncSanner/master/SQLTrunc3.png)

## But How?
I will try to explain my current implementation, this might not be the best way and I'm very open to improvements. The current scanner can have false-positives. The scanner will launch a request and fetch the response based on your original request. The scanner will then calculate a baseline based on the Response Code and Response Length.

Once the baseline is established, threading is kicked off for the paramter fuzzing which happens in a new class. The fuzzing will loop each parameter and loop a payload set of 5 --> 10 --> 15 --> 20 --> 30 --> 40 characters. Whenever the response is different from the baseline an issue will be raised with the parameter and payload set found potentially vulnerable.

## Todo

- [ ] This might break usage in Community Edition, but a passive scanner needs to be invoked instead of the current implementation.
- [ ] Better threading as the current implementation is horrible.
- [ ] Burp Issue currently do not receive the HTTP Message from the check, and displays the original request, needs to be fixed.
- [ ] Cleanup, very messy at the moment

