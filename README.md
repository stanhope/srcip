srcip
=====

Simple libpcap app for capturing and publishing scrip/port/agent over redis channel

* Server is hard-coded to `127.0.0.1`.
* Pubsub is hard-coded to `checkip` channel.

Usage:

```
sudo ./srcip [-a] [-d] [-h] -i INTERFACE [filter...]

   [-a] - enable user agent tracking (not working yet), applies only to tcp port 80 w/ custom filter
   [-d] - enable debugging
   [-h] - show usage
   [filter...] - default is 'tcp port 80 and tcp[13] == 2'
```




