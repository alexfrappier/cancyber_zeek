#RPM/RedHat-based Linux

sudo yum -y install cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python-devel swig zlib-devel


git clone --recursive https://github.com/zeek/zeek
cd zeek
./configure
make
sudo make install


#ubuntu/Debian
sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev

git clone --recursive https://github.com/zeek/zeek
cd zeek
./configure
make
sudo make install


#FreeBSD
sudo pkg install bash cmake swig30 bison python py27-sqlite3 py27-ipaddress

git clone --recursive https://github.com/zeek/zeek
cd zeek
./configure
make
sudo make install


#MacOS
brew install zeek (install brew from https://brew.sh/
