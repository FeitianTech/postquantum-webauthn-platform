sudo apt-get install -y git libssl-dev make cmake build-essential python3-pip

git clone https://github.com/open-quantum-safe/liboqs-python
sudo pip3 install liboqs-python/. --upgrade --break-system-packages
sudo python3 -c "import oqs"
