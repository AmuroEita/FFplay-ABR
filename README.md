FFmpeg-ABR README
=============

FFmpeg-ABR is a multimedia content for ABR research, based on FFmpeg, typically used for DASH/HLS adaptive bitrate testing.


## Getting Started

### Prerequisites

Ubuntu 22.0.4

* Libtensorflow
  ```sh
  wget https://storage.googleapis.com/tensorflow/libtensorflow/libtensorflow-gpu-linux-x86_64-2.6.0.tar.gz
  sudo tar -C /usr/local -xzf libtensorflow-gpu-linux-x86_64-2.6.0.tar.gz
  ```

* Libpcap-dev
  ```sh
  sudo apt-get install libpcap-dev
  ```

* Libxml 2.0
  ```sh
  sudo apt-get install libxml2-dev
  ```

* Libssl-dev
  ```sh
  sudo apt-get install libssl-dev
  ```

* Libsdl2-dev
  ```sh
  sudo apt-get install libsdl2-dev
  ```

### Compile

```sh
sh build.sh
```

### Play

```sh
./ffplay -abr -abr-params format=dash ffabr:$(dash source url)
```


### Pcap capture
```
sudo gcc parser.c -lpcap -o parser && sudo setcap cap_net_raw+eip parser

sudo tcpdump -i wlp0s20f3 -s 0 -A 'tcp dst port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'
```