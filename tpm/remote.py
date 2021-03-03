#!/usr/bin/python
#from threading import thread 
import argparse
import sys
import pprint
import logging
import subprocess
import json
import re
import time
import os
import signal  
import time
from connection import Connection 
import shutil
from nose.tools import assert_equal

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=logging.DEBUG)
VERSION='1.0.0'
_UNI_ERR_RESP = 'replace'


class SCP(Connection):
    def __init__(self,command,file_name,is_connect):
        super().__init__(command, file_name,is_connect)

class ATF(Connection):
    def __init__(self,command,file_name,is_connect):
        super().__init__(command,file_name,is_connect)
        
class CPU(Connection):
    def __init__(self,command,file_name,is_connect):
        super().__init__(command,file_name,is_connect)

class BMC(Connection):
    def __init__(self,command,file_name,is_connect):
        super().__init__(command,file_name,is_connect)
        

class Remote:
    def __init__(self,scp_instance_0,scp_instance_1,atf_instance,cpu_instance,bmc_instance, bmc_ip,host, username='root', password='root',ssh_port=22,timeout=600, debug=False):
        self.debug=debug
        self.scp_instance_0=scp_instance_0
        self.scp_instance_1=scp_instance_1
        self.atf_instance=atf_instance
        self.cpu_instance=cpu_instance
        self.bmc_instance=bmc_instance
        self.logger = logging.getLogger("TPM")
        self.logger.setLevel(logging.DEBUG)
        self.host=host
        self.bmc_ip=bmc_ip
        self.username=username
        self.password=password
        self.ssh_port=ssh_port
        self.timeout_login_sut=timeout
    
    def connect_console(self):
        self.scp_instance_0.connect()
        self.scp_instance_1.connect()
        self.atf_instance.connect()
        self.cpu_instance.connect()
        self.bmc_instance.connect()
    def prepare_sut(self):
        cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN sol deactivate instance=1"
        rc, data = self.system_run_command(cmd)
        try: 
            assert_equal(rc,0,'Can not deactivate SOL instance =1')
        except:
            assert_equal(rc,1,'Can not deactivate SOL instance =1')
            
        cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN sol deactivate instance=2"
        rc, data = self.system_run_command(cmd)
        try: 
            assert_equal(rc,0,'Can not deactivate SOL instance =2')
        except:
            assert_equal(rc,1,'Can not deactivate SOL instance =2')
        cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN sol deactivate instance=3"
        rc, data = self.system_run_command(cmd)
        try: 
            assert_equal(rc,0,'Can not deactivate SOL instance =3')
        except:
            assert_equal(rc,1,'Can not deactivate SOL instance =3')
        cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN sol deactivate instance=4"
        rc, data = self.system_run_command(cmd)
        try: 
            assert_equal(rc,0,'Can not deactivate SOL instance =4')
        except:
            assert_equal(rc,1,'Can not deactivate SOL instance =4')
        cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN chassis power reset"
        rc, data = self.system_run_command(cmd)
        assert_equal(rc,0,'Can not dp power reset action ')
    def reset_sut(self):
        cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN chassis power reset"
        rc, data = self.system_run_command(cmd)
        if rc==0:
            self.logger.info(f"power reset CPU successfully")
        else:
            cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN chassis power off"
            rc, data = self.system_run_command(cmd)
            time.sleep(30)
            cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN chassis power on"
            rc, data = self.system_run_command(cmd)
            if rc !=0:
                rc, data = self.system_run_command(cmd)
                self.logger.error(f"power reset CPU failed")
                sys.exit(2)
    def handler(self,signum, frame):
        self.logger.error("Timeout to connect to CPU OS is expired")
        sys.exit(2)
        #self.reset_sut()
        #return False  

    def ssh_cmd(self,command):
        ssh_args = (
            "-o ServerAliveInterval=300 -o StrictHostKeyChecking=no"
            + " -o UserKnownHostsFile=/dev/null"
            + " -o LogLevel=error -o ConnectTimeout=30 -p "
            + self.ssh_port
        )
        data = {
            "user": self.username,
            "host": self.host,
            "password": self.password,
            "commands": command,
            "ssh_args": ssh_args,
        }
        command = (
            "sshpass -p {password} ssh {ssh_args} "
            + "{user}@{host} {commands}"
        )
        return_code,output = self.system_run_command(command.format(**data))
        return return_code, output
    
    def system_run_command(self, cmd):
        #self.logger.info(f"CMD: {cmd}")
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
        )
        full_output = proc.stdout.decode("utf-8", _UNI_ERR_RESP)
        if proc.stderr is not None:
            full_error = proc.stderr.decode("utf-8", _UNI_ERR_RESP)
        else:
            full_error = ""
        return proc.returncode, "%s%s".strip('\n\t') % (full_output, full_error)
        
    def scp_get(self,source, target):
       scp_args = (
           "-o ServerAliveInterval=300 -o StrictHostKeyChecking=no "
           + "-o UserKnownHostsFile=/dev/null -o LogLevel=error "
           + "-o ConnectTimeout=30 -P "
           + self.ssh_port
       )
       data = {
           "user": self.username,
           "host": self.host,
           "password": self.password,
           "scp_args": scp_args,
           "source": source,
           "target": target,
       }
       command = (
           "sshpass -p {password} scp {scp_args} -r"
           + " {user}@{host}:{source} {target}"
       )
       return_code, out = self.system_run_command(command.format(**data))
       return return_code, out
    def get_data(self,file):
        while True: 
            if not self.is_cpu_live():
                self.reset_sut()
            else:
                break
        target='.'
        source=file
        rc,data=self.scp_get(source,target)
        if rc !=0:
            self.logger.error(f"can not get {source} file from CPU ")
        else:
            self.logger.info(f"get {source} file from CPU successfully")
    def preapare_data(self):
        while True: 
            if not self.is_cpu_live():
                self.reset_sut()
            else:
                break
        cmd="find . -name 'tpm.py'"
        rc, tpm_script=self.system_run_command(cmd)
        self.logger.info(f"data {tpm_script}")
        if rc !=0:
            self.logger.error(f"do not find tpm.py script {tpm_script}")
        rc, out = self.scp_put(tpm_script,'/tmp/')
        if rc !=0:
            self.logger.error(f"do not put tpm.py script to test system {out}")
            sys.exit(3)
        else:
            self.logger.info("put tpm.py script to CPU OS successfully")
    def scp_put(self, source, target):
        scp_args = (
            "-o ServerAliveInterval=300 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=error -o ConnectTimeout=30 -P %s"% self.ssh_port
        )
        data = {
            "user": self.username,
            "host": self.host,
            "password": self.password,
            "scp_args": scp_args,
            "source": source,
            "target": target,
        }
        command = "sshpass -p {password} scp -r {scp_args} {source}  {user}@{host}:{target}"
        return_code, out = self.system_run_command(command.format(**data).replace('\n',''))
        return return_code, out 
    def close_console(self,file_name_log):
        name=f"{file_name_log}_scp_master_console_log.txt"
        self.scp_instance_0.disconnect(name)
        name=f"{file_name_log}_scp_slave_console_log.txt"
        self.scp_instance_1.disconnect(name)
        name=f"{file_name_log}_atf_master_console_log.txt"
        self.atf_instance.disconnect(name)
        name=f"{file_name_log}_cpu_master_console_log.txt"
        self.cpu_instance.disconnect(name)
        name=f"{file_name_log}_bmc_master_console_log.txt"
        self.bmc_instance.disconnect(name)    
    
    def is_cpu_live(self):
        # Register the signal function handler
        #signal.signal(signal.SIGALRM, self.handler)
        #signal.alarm(self.timeout_login_sut)
        cmd='echo "welcome to CPU OS"'
        time_out=0
        is_live=False 
        while time_out < self.timeout_login_sut:
            rc,output=self.ssh_cmd(cmd)
            if rc ==0:
                self.logger.info('CPU has been lived:     %s'%output)
                is_live=True 
                break
            self.logger.info("waiting CPU alive")
            time.sleep(3)
            time_out +=time_out
        if not is_live:
            self.logger.error("FAIL to connect to CPU OS")
        return is_live 
        
    def check_tpm(self,file):
        while True: 
            if not self.is_cpu_live():
                self.reset_sut()
            else:
                break 
        cmd=f"python3 /tmp/tpm.py --file {file}"
        self.ssh_cmd(cmd)
        
def is_valid_ip(ip):
    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$")
    is_ip= pat.match(ip)
    if is_ip:
        return True 
    else:
        return False
        
        
        
def main():
    parser = argparse.ArgumentParser(description='check TPM')
    parser.add_argument('--host', help='IP host of test CPU',type=str, default='', required=True)
    parser.add_argument('--bmc_ip', help='IP host of test BMC',type=str, default='', required=True)
    parser.add_argument('--number_times', help='set number times to measure PCR data',type=int, default=1, required=True)
    parser.add_argument('--username', help='username login OS of CPU',type=str,default='root')
    parser.add_argument('--password', help='password to login test system',type=str,default='root')
    parser.add_argument('--ssh_port', help='ssh port to login test system',type=str, default='22')
    parser.add_argument('--time_login_sut', help='timeout try to login to CPU OS',type=int, default=600)
    parser.add_argument('--config_file', help='file configure of SUT',type=str, default='sut_tpm.json' )
    args = vars(parser.parse_args())
    host=args['host']
    bmc_ip=args['bmc_ip']
    username=args['username']
    password=args['password']
    ssh_port=args['ssh_port']
    time_out=args['time_login_sut']
    number_times=args['number_times']
    if not is_valid_ip(host):
        sys.stderr.write("Error:  validation IP is failed \n")
        sys.stderr.flush()
        sys.exit(1)
    file_config=args['config_file']
    if not os.path.exists(file_config):
        print ("configuration board file is not exist")
        sys.exit(1)
        
    try:
        json_data=open(file_config)
        jdata = json.load(json_data)
        scp_master_connect=jdata['scp_master_connect']
        scp_slave_connect=jdata['scp_slave_connect']
        bmc_connect=jdata['bmc_connect']
        cpu_connect=jdata['cpu_connect']
        atf_connect=jdata['atf_connect']
    except:
        sys.stderr.write("Error: format of board configuration file is not correct \n")
        sys.stderr.flush()
        sys.exit(1)
        
    
    timestr = time.strftime("%Y%m%d-%H%M%S")
    scp_master_filename = 'scp_console_master_log_'+timestr+".txt"
    scp_slave_filename = 'scp_console_slave_log_'+timestr+".txt"
    atf_filename = 'atf_console_log_'+timestr+".txt"
    cpu_filename = 'cpu_console_log_'+timestr+".txt"
    bmc_filename = 'bmc_console_log_'+timestr+".txt"
    scp_0=SCP(scp_master_connect,scp_master_filename,1)
    scp_1=SCP(scp_slave_connect,scp_slave_filename,2)
    cpu=CPU(cpu_connect,cpu_filename,1)
    bmc=BMC(bmc_connect,bmc_filename,1)
    atf=ATF(atf_connect,atf_filename,2)
    
    path = os.getcwd()
    path_each_run=f"{path}/separate_log"
    if not os.path.exists(path_each_run):
            os.makedirs(path_each_run)   
    filename_date = 'tpm_log_'+timestr+".txt"    
    remote=Remote(scp_0,scp_1, atf, cpu, bmc,bmc_ip,host, username=username, password=password,ssh_port=ssh_port,timeout=time_out)
    remote.prepare_sut()
    time.sleep(30)
    pass_cycles=list()
    fail_cycles=list()
    for index in range(0,number_times):
        remote.logger.info(f"checking read all PCRs at number: {index}")
        file_name_log=f"{path_each_run}/{timestr}_{index}"
        remote.connect_console()
        filename=f"/tmp/number_{index}_{filename_date}"
        remote.preapare_data()
        remote.check_tpm(filename)
        remote.get_data(filename)
        remote.reset_sut()
        #time.sleep(60)
        remote.logger.info("checking results")
        cmd=f"diff number_0_{filename_date} number_{index}_{filename_date}"
        rc,data=remote.system_run_command(cmd)
        if rc==0:
            remote.logger.info("PASS")
            pass_cycles.append(index)
        else:
            remote.logger.info ("FAIL")
            remote.logger.info (f"data compare: {data}")
            fail_cycles.append(index)
        remote.close_console(file_name_log)
    remote.logger.info (f"Number check times: {number_times}")
    remote.logger.info (f"PASS times : {len(pass_cycles)}")
    remote.logger.info (f"PASS cycles : {pass_cycles}")
    remote.logger.info (f"FAIL times : {len(fail_cycles)}")
    remote.logger.info (f"FAIL cycles : {fail_cycles}")
    
             
if  __name__ == '__main__':
    main()
