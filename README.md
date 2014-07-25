srcip
=====

Simple libpcap app for capturing and publishing scrip/port/agent over redis channel

* Server is hard-coded to `127.0.0.1`.

Usage:

```
sudo ./srcip [-a CHANNEL] [-c CHANNEL] [-d] [-h] -i INTERFACE [filter...]
   [-a CHANNEL] - enable user agent tracking and channel to publish to
                  partially working. Applies only when filter includes 'tcp port 80'
   [-c CHANNEL] - pubsub channel, defaults to 'srcip'
   [-d]         - enable debug output
   [-h]         - show this help message
   [-s SERVER]  - change the server (defaults to 127.0.0.1)
   [filter...]  - default is 'tcp port 80 and tcp[13] == 2'
```




