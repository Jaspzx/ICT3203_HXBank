# HX Bank

## To Access the web portal
[HX Bank](https://hxbank.tk)

## Installation
1. Clone the repository
2. Open terminal in the cloned repository and run the script below
```
pip3 install virtualenv
python -m venv venv-win
venv-win\Scripts\Activate
pip install -r requirements.txt
```
3. Run the program
```

flask seed run
python main.py
```

### Docker Commands
To build and start the docker container. Run:
```
docker compose up -d
```
To stop and remove all the containers and images. Run:
```
docker compose down --rmi local
```
Test webhook