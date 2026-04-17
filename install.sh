#!/bin/bash

echo "[+] Installing ReconX dependencies..."

sudo apt update
sudo apt install golang -y
pip install requests colorama tqdm

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

export PATH=$PATH:$(go env GOPATH)/bin

echo "[+] Installation complete!"
