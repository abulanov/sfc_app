install:
	pip install -r requirements.txt
	apt install -y curl
	apt install -y traceroute

clean:
	rm -rf __pycache__
