# Watts Dog HIDS
This is a HIDS (Hardware Intrution Detection System) Build for watts to keep a track of changes hapening to the homegrid controller 

## Setup 
Setup methots for the system
### Normal setup 
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
#### Make dayly scan

Make and open the cronjob file
```shell
sudo nano /etc/cron.d/dayly_scan
```
Paste this code with the path of the file maching were the main.py file is
```shell
20 6 * * * root /usr/bin/python3 /home/lukas/watts_dog/main.py full_scan
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
0 * * * * root /usr/bin/python3 /home/lukas/watts_dog/main.py small_scan
```
Make shure the file dose not have eany permitions that it dose not need
```shell
sudo chmod 600 /etc/cron.d/small_scan
sudo chown root:root /etc/cron.d/small_scan
```