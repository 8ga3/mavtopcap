# mavtopcap
convert a MAVLink tlog file to a Wireshark pcap file

[QGroundControl](http://qgroundcontrol.com/)や[Mission Planner](https://ardupilot.org/planner/)で作成される、テレメトリーログ(tlog)を[Wireshark](https://www.wireshark.org/)で表示できるpcap形式に変換します。

[pymavlink](https://github.com/ArduPilot/pymavlink)のexamplesに[mav2pcap.py](https://github.com/ArduPilot/pymavlink/blob/master/examples/mav2pcap.py)は存在しますが、MAVLink v2.0に対応していないのと動作が遅いので作成することにしました。

tlog以外のpymavlinkで読めるフォーマット（.bin .px4log .log .raw .mavlink）を読み込めると思いますがテストしていません。

リアルタイムでMAVLinkメッセージをキャプチャしたい場合は、Wiresharkに[MAVLinkプラグイン](https://mavlink.io/en/guide/wireshark.html)をインストールしてキャプチャしたほうがよいと思うので、このスクリプトでは対応させてません。

# Installation

python3とpymavlinkをインストールします。（pymavlinkはpython2も動作対象ですが、mavtocap.pyはpython2での確認はしていません。）
詳しくは[こちら](https://github.com/ArduPilot/pymavlink)を参照してください。

~~~
% python3 -m pip install pymavlink
~~~

# usage

~~~
usage: mavtopcap.py [-h] [-p prefix] input_files [input_files ...]

convert a MAVLink tlog file to a Wireshark pcap file

positional arguments:
  input_files

optional arguments:
  -h, --help            show this help message and exit
  -p prefix, --pre prefix
                        file name prefix
~~~