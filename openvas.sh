#!/bin/bash
# 
# Sistema operacional - DEBIAN 10 
#
# Author: Ricardo Ribeiro Tavares (@1RicardoTavares)
# License: BSD 3-Clause
# https://github.com/1RicardoTavares/
#
 
####################################
# Antes de iniciar
####################################
# Adicione seu usuario ao grupo sudo
# su -
# adduser <user> sudo 
# shutdown -r now
#
# Configure o LOCALE
# sudo bash -c 'echo LANGUAGE="en_US.UTF-8" > /etc/environment'
# sudo bash -c 'echo LC_ALL="en_US.UTF-8" >> /etc/environment'
#
# Este script deverá ser executado com o usuário root

####################################
# INSTALAR REQUISITOS
####################################
sudo apt update ;\
sudo apt -y dist-upgrade ;\
sudo apt -y autoremove ;\
sudo apt install -y software-properties-common ;\
sudo DEBIAN_FRONTEND=noninteractive apt install -y cmake pkg-config libglib2.0-dev libgpgme-dev libgnutls28-dev \
uuid-dev libssh-gcrypt-dev libldap2-dev doxygen graphviz libradcli-dev libhiredis-dev libpcap-dev bison \
libksba-dev libsnmp-dev gcc-mingw-w64 heimdal-dev libpopt-dev xmltoman redis-server xsltproc libical-dev postgresql \
postgresql-contrib postgresql-server-dev-all gnutls-bin nmap rpm nsis curl wget fakeroot gnupg \
sshpass socat snmp smbclient libmicrohttpd-dev libxml2-dev python-polib gettext rsync xml-twig-tools \
python3-paramiko python3-lxml python3-defusedxml python3-pip python3-psutil virtualenv vim git ;\
sudo apt install -y texlive-latex-extra --no-install-recommends ;\
sudo apt install -y texlive-fonts-recommended ;\
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add - ;\
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list ;\
sudo apt update ;\
sudo apt -y install yarn

####################################
# CRIA USUARIO GVM
####################################
echo 'export PATH="$PATH:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin"' | sudo tee -a /etc/profile.d/gvm.sh ;\
sudo chmod 0755 /etc/profile.d/gvm.sh ;\
source /etc/profile.d/gvm.sh ;\
sudo bash -c 'cat << EOF > /etc/ld.so.conf.d/gvm.conf
# gmv libs location
/opt/gvm/lib
EOF'

sudo mkdir /opt/gvm ;\
sudo adduser gvm --disabled-password --home /opt/gvm/ --no-create-home --gecos '' ;\
sudo usermod -aG redis gvm ;\
sudo chown gvm:gvm /opt/gvm/

#Executa os passos com o usuario GVM
sudo -i -u gvm bash << EOFGVM

mkdir src ;\
cd src ;\
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH

####################################
# DOWNLOAD DAS FERRAMENTAS GREENBONE
####################################
git clone -b gvm-libs-20.08 --single-branch  https://github.com/greenbone/gvm-libs.git ;\
git clone -b openvas-20.08 --single-branch https://github.com/greenbone/openvas.git ;\
git clone -b gvmd-20.08 --single-branch https://github.com/greenbone/gvmd.git ;\
git clone -b master --single-branch https://github.com/greenbone/openvas-smb.git ;\
git clone -b gsa-20.08 --single-branch https://github.com/greenbone/gsa.git ;\
git clone -b ospd-openvas-20.08 --single-branch  https://github.com/greenbone/ospd-openvas.git ;\
git clone -b ospd-20.08 --single-branch https://github.com/greenbone/ospd.git

####################################
# INSTALAR GVM-LIBS
####################################
cd gvm-libs ;\
 export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 mkdir build ;\
 cd build ;\
 cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm .. ;\
 make ;\
 make doc ;\
 make install ;\
 cd /opt/gvm/src

####################################
# INSTALAR OPENVAS-SMB
####################################
cd openvas-smb ;\
 export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 mkdir build ;\
 cd build/ ;\
 cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm .. ;\
 make ;\
 make install ;\
 cd /opt/gvm/src

####################################
# INSTALAR SCANNER
####################################
cd openvas ;\
 export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 mkdir build ;\
 cd build/ ;\
 cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm .. ;\
 make ;\
 make doc ;\
 make install ;\
 cd /opt/gvm/src

EOFGVM
####################################
# CONFIGURAR REDIS 
####################################
#Executar os passos com usuário root
ldconfig ;\
cp /etc/redis/redis.conf /etc/redis/redis.orig ;\
cp /opt/gvm/src/openvas/config/redis-openvas.conf /etc/redis/ ;\
chown redis:redis /etc/redis/redis-openvas.conf ;\
echo "db_address = /run/redis-openvas/redis.sock" > /opt/gvm/etc/openvas/openvas.conf ;\
systemctl enable redis-server@openvas.service ;\
systemctl start redis-server@openvas.service

sysctl -w net.core.somaxconn=1024 ;\
sysctl vm.overcommit_memory=1

echo "net.core.somaxconn=1024"  >> /etc/sysctl.conf ;\
echo "vm.overcommit_memory=1" >> /etc/sysctl.conf

cat << EOF > /etc/systemd/system/disable-thp.service
[Unit]
Description=Disable Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload ;\
systemctl start disable-thp ;\
systemctl enable disable-thp ;\
systemctl restart redis-server

cp /etc/sudoers /etc/sudoers.original ;\
sed -i -e 's/secure_path=.*in/&:\/opt\/gvm\/sbin/' /etc/sudoers

echo 'gvm ALL = NOPASSWD: /opt/gvm/sbin/openvas' >> /etc/sudoers ;\
echo 'gvm ALL = NOPASSWD: /opt/gvm/sbin/gsad' >> /etc/sudoers

####################################
# ATUALIZAR NVT
# UPLOAD DE PLUGINS
# INSTALA O MANAGER
####################################
#Executa os passos com o usuario GVM
sudo -i -u gvm bash << EOFGVM 
greenbone-nvt-sync
sudo openvas -u
cd /opt/gvm/src/gvmd ;\
 export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 mkdir build ;\
 cd build/ ;\
 cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm .. ;\
 make ;\
 make doc ;\
 make install ;\
 cd /opt/gvm/src
EOFGVM

####################################
# CONFIGURAR POSTGRESQL
####################################
#Executa os passos com o usuario POSTGRES
sudo -i -u postgres bash << EOFPOSTGRES
createuser -DRS gvm
createdb -O gvm gvmd

psql gvmd << EOF
create role dba with superuser noinherit;
grant dba to gvm;
create extension "uuid-ossp";
create extension "pgcrypto";
EOF

EOFPOSTGRES

####################################
# AJUSTES EM CERTIFICADOS
# CRIACAO DE USUARIO ADMIN
# CONFIGURA E ATUALIZA OS FEEDS
# INSTALAR GSA
# INSTALAR OSPD-OPENVAS
####################################
#  VER chmod 777 /opt/gvm/var/log/gvm/gvmd.log

#Executa os passos com o usuario GVM
sudo -i -u gvm bash << EOFGVM

cd /opt/gvm/src ;\
gvm-manage-certs -a ;\
gvmd --create-user=admin --password=Aluno ;\
gvmuuid=`gvmd --get-users --verbose | cut -d ' ' -f2` ;\
gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value $gvmuuid

greenbone-feed-sync --type GVMD_DATA ;\
greenbone-feed-sync --type SCAP ;\
greenbone-feed-sync --type CERT

cd gsa ;\
 export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 mkdir build ;\
 cd build/ ;\
 cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm .. ;\
 make ;\
 make doc ;\
 make install ;\
 touch /opt/gvm/var/log/gvm/gsad.log ;\
 cd /opt/gvm/src

cd /opt/gvm/src ;\
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH ;\
virtualenv --python python3.7  /opt/gvm/bin/ospd-scanner/ ;\
source /opt/gvm/bin/ospd-scanner/bin/activate

mkdir /opt/gvm/var/run/ospd/ ;\
cd ospd ;\
pip3 install . ;\
cd /opt/gvm/src

cd ospd-openvas ;\
pip3 install . ;\
cd /opt/gvm/src
EOFGVM

####################################
# STARTUP SCRIPTS
####################################
#Executa os passos com o usuario ROOT
cat << EOF > /etc/systemd/system/gvmd.service
[Unit]
Description=Open Vulnerability Assessment System Manager Daemon
Documentation=man:gvmd(8) https://www.greenbone.net
Wants=postgresql.service ospd-openvas.service
After=postgresql.service ospd-openvas.service

[Service]
Type=forking
User=gvm
Group=gvm
PIDFile=/opt/gvm/var/run/gvmd.pid
WorkingDirectory=/opt/gvm
ExecStart=/opt/gvm/sbin/gvmd --osp-vt-update=/opt/gvm/var/run/ospd.sock
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=2min
KillMode=process
KillSignal=SIGINT
GuessMainPID=no
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/gsad.service
[Unit]
Description=Greenbone Security Assistant (gsad)
Documentation=man:gsad(8) https://www.greenbone.net
After=network.target
Wants=gvmd.service


[Service]
Type=forking
PIDFile=/opt/gvm/var/run/gsad.pid
WorkingDirectory=/opt/gvm
ExecStart=/opt/gvm/sbin/gsad --drop-privileges=gvm
Restart=on-failure
RestartSec=2min
KillMode=process
KillSignal=SIGINT
GuessMainPID=no
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/ospd-openvas.service 
[Unit]
Description=Job that runs the ospd-openvas daemon
Documentation=man:gvm
After=network.target redis-server@openvas.service
Wants=redis-server@openvas.service

[Service]
Environment=PATH=/opt/gvm/bin/ospd-scanner/bin:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Type=forking
User=gvm
Group=gvm
WorkingDirectory=/opt/gvm
PIDFile=/opt/gvm/var/run/ospd-openvas.pid
ExecStart=/opt/gvm/bin/ospd-scanner/bin/python /opt/gvm/bin/ospd-scanner/bin/ospd-openvas --pid-file /opt/gvm/var/run/ospd-openvas.pid --unix-socket=/opt/gvm/var/run/ospd.sock --log-file /opt/gvm/var/log/gvm/ospd-scanner.log --lock-file-dir /opt/gvm/var/run/ospd/
Restart=on-failure
RestartSec=2min
KillMode=process
KillSignal=SIGINT
GuessMainPID=no
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload ;\
systemctl enable gvmd ;\
systemctl enable gsad ;\
systemctl enable ospd-openvas ;\
systemctl start gvmd ;\
systemctl start gsad ;\
systemctl start ospd-openvas

systemctl status gvmd ;\
systemctl status gsad ;\
systemctl status ospd-openvas

#Executa os passos com o usuario GVM
#VERIFICAR MODIFICACAO AQUI
sudo -i -u gvm bash << EOFGVM
gvmscanner=`gvmd --get-scanners | head -n 1 | cut -d ' ' -f1` ;\
gvmd --modify-scanner=$gvmscanner --scanner-host=/opt/gvm/var/run/ospd.sock

EOFGVM

systemctl restart gvmd ;\
systemctl restart gsad ;\
systemctl restart ospd-openvas
