srcip
=====

Simple libpcap app for capturing and publishing scrip/port/agent over redis channel

* Server is hard-coded to `127.0.0.1`.

Usage:

```
sudo ./srcip [-a CHANNEL] [-c CHANNEL] [-d] [-h] -i INTERFACE [filter...]
   [-a CHANNEL] - enable user agent tracking (partially working) and channel [default 'ua', applies only to tcp port 80\
   [-c CHANNEL] - pubsub channel, defaults to 'srcip'
   [-d] - enable debug output
   [-h] - show this help message
   [filter...] - default is 'tcp port 80 and tcp[13] == 2'
```




