# Network Monitoring Solution with Python

This project sniffs network packets on a certain device and broadcasts the
packets to the backend via websockets which is later forwarded to any
subscribe clients on the socket

## How it works

1. [Start the virtual environment](#start-virtual-environment)
2. [Install dependencies](#installing-dependencies)
3. [Start Backend server](#starting-backend-server)
4. [Start Sniffer](#start-the-packets-sniffer-on-another-terminal)

### Start Virtual Environment

#### Create Virtual Environment (First time only)

```
python -m venv .venv
```

#### Activate the Virtual Environment

```
./.venv/bin/activate
```

### Installing Dependencies

```
pip install -r requirements.txt
```

### Starting Backend Server

```
python main.py
```

### Start the packets sniffer on another terminal

NB: you may need to enter the virtual environment before starting the sniffer

```
python sniffer.py
```

or (Linux only)

```
sudo python sniffer.py
```
