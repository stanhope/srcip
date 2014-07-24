srcip
=====

Simple libpcap app for capturing and publishing scrip/port/agent over redis channel

* Channel is hard-coded to `checkip`.
* Server is hard-coded to `127.0.0.1`.

Usage:

```
sudo ./srcip [-d] [-h] -i INTERFACE [filter...]

   [-d] - enable debugging
   [-h] - help
   [-a] - track user agents (only vald
   [filter...] - default is 'tcp port 80 and tcp[13] == 2'
```




