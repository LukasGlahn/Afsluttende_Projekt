# Watts Dog HIDS
This is a HIDS (Hardware Intrution Detection System) Build for watts to keep a track of changes hapening to the homegrid controller 

## Setup 
Setup methots for the system
### Normal setup 
#### Setup Wattsdog_hub
to use the wattsdog software you have too make a server for it to conect too, so it can validate that the scaner has not bean chanegd or to reset the scaner remotly. <br>
Make a privat key for the docker container
```shell
openssl req -new -x509 -nodes -out server.crt -keyout server.key -subj "/CN=localhost"
```
build the docker container
```shell
docker build -t wattsdog_hub .
```  
run the docker container and provide a password for reseting controlers
```shell
docker run -d -e ADMIN_PASSWORD=<secret password> -p 5125:5125 wattsdog_hub
```
#### Setup Wattsdog_conecter
For the software to be able to conect to the server and have a isolation stage a docker container is made to handel the conection betwean the server and the scaner <br>
On the homegrid controler build container
```shell
docker build -t wattsdog_hub .
```  
Run container and provide the ip of were wattsdog hub is.
```shell
docker run -e SERVERIP=<serverip>  -d --network host wattsdog_conector
```
#### checking cronjob is installed
check if cron is installed
```shell
dpkg -l cron 
```
If not install cron with apt
```shell
apt-get install cron
```
Verify if the cron service is running
```shell
systemctl status cron
```
#### install clamav
install clamav
```shell
apt install clamav
```
check that it is running
```shell
sudo systemctl status clamav
```
#### Make dayly scan

Make and open the cronjob file
```shell
sudo nano /etc/cron.d/dayly_scan
```
Paste this code with the path of the file maching were the main.py file is
```shell
20 6 * * * root /usr/bin/python3 <main script folder path>/main.py full_scan
```
Make shure the file dose not have eany permitions that it dose not need
```shell
sudo chmod 600 /etc/cron.d/dayly_scan
sudo chown root:root /etc/cron.d/dayly_scan
```

#### make a small houerly scan

Make and open the cronjob file
```shell
sudo nano /etc/cron.d/small_scan
```
Paste this code with the path of the file maching were the main.py file is<br>
make the small scan happen at a intervall that puts it well before a big scan can happen to avoid them goving over eachother
```shell
0 * * * * root /usr/bin/python3 <main script folder path>/main.py small_scan
```
Make shure the file dose not have eany permitions that it dose not need
```shell
sudo chmod 600 /etc/cron.d/small_scan
sudo chown root:root /etc/cron.d/small_scan
```

## Tuning the file scan

The file scaner works by taking the structure.json file as a way to define were a scan is gonna happen and if spesific sub directorys will have difrent rules. <br>

### The structure off structure.json will be as folows.

#### Root directory - a directory that will be the root of a spesifik rule set that all directorys uder will use (in the exsampel /home),

#### Default rules - the first element under a root directory will be the rules that will be standard on all file scans.<br>

"checks" - a string to indekate waht will be checked on with the letters H, P and U that stands for<br>

H for Hash - hash is to check for a change in the content of a file offen don with a hash but som files are not able to be hashed so can also indikate like wise changes. If a file can not be compaierd it will just be null still making sure a file dose not change to a difrent type.<br>

P for Permitions - Permitions are your normal rules like 777 or 644 to indicate waht a user, grupe or all users are alowd to do.<br>

U for users - users is for checking that the user or grupe that owns a file dos not change.<br>

"severity" - is for the waning level that will be used on the system so if its 0 it will be a normal warning and if its 5 its a emerg sevarety in journald

#### Exceptions is for directory exseptions like if a directory and its sub directorys schoud not use file entecrety checks

in the exsample we see `/home/exsample` were the checks is only "pu" so it wont check the hashing of the files. <br>

or in `/home/imworkinghere` were checks is empty so all files will be ignored.

#### file_exceptions is for file exseptions like if a file schoud not use file entecrety checks and works mostly the same as exceptions just only on one file

```json
{
    "/home": {
        "default": {
            "checks": "hpu",
            "severity": 3
        },
        "exceptions": {
            "/home/exsample": {
                "checks": "pu",
                "severity": 3
            },
            "/home/imworkinghere": {
                "checks": "",
                "severity": 0
            }
        },
        "file_exceptions": {
            "/home/onefliejens/log.log": {
                "checks": "pu",
                "severity": 1
            },
        }
    }
}
```