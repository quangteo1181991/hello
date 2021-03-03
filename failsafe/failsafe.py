#!/usr/bin/python
#from threading import thread 
#nvparm -r -o 0x118020
#NV_SI_WDT_BIOS_EXP_MINS: NV_SI_WDT_BIOS_EXP_MINS        = (4 * 8) + NV_USER_PARAM_START
#36*8 + NV_USER_PARAM_START 120
#nvparm -r -o 0x118020 --> SCP 
#nvparm -r -o 0x118120
#nvparm -s 0x1 -o 0x1f0020
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
from time import sleep
from datetime import datetime
import pexpect

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=logging.DEBUG)
VERSION='1.0.0'
_UNI_ERR_RESP = 'replace'

atf_child = pexpect.spawn("ipmitool -H 10.38.131.135 -U ADMIN -P ADMIN -I lanplus sol activate instance=3")
scp_child = pexpect.spawn("telnet 10.38.131.8 7014")
os_child = pexpect.spawn("telnet 10.38.131.8 7007")


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
    def __init__(self,scp_instance_0,scp_instance_1,atf_instance,cpu_instance,bmc_instance, bmc_ip,host, username='root', password='root',timeout=600):
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
        self.timeout_login_sut=timeout
    
    def connect_console(self):
        self.scp_instance_0.connect()
        self.scp_instance_1.connect()
        self.atf_instance.connect()
        self.cpu_instance.connect()
        self.bmc_instance.connect()
    def prepare_sut(self):
        cmd=f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus raw 0x32 0x91 0x01"
        rc, data = self.system_run_command(cmd)
        assert_equal(rc,0,'Can not enable root account')
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
        #cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN sol deactivate instance=3"
        #rc, data = self.system_run_command(cmd)
        #try: 
        #    assert_equal(rc,0,'Can not deactivate SOL instance =3')
        #except:
        #    assert_equal(rc,1,'Can not deactivate SOL instance =3')
        cmd=f"ipmitool -I lanplus -H {self.bmc_ip} -U ADMIN -P ADMIN sol deactivate instance=4"
        rc, data = self.system_run_command(cmd)
        try: 
            assert_equal(rc,0,'Can not deactivate SOL instance =4')
        except:
            assert_equal(rc,1,'Can not deactivate SOL instance =4')
    def bmc_ssh_cmd(self,command):
        ssh_args = (
            "-o ServerAliveInterval=300 -o StrictHostKeyChecking=no"
            + " -o UserKnownHostsFile=/dev/null"
            + " -o LogLevel=error -o ConnectTimeout=30 -p 22"
        )
        data = {
            "user": self.username,
            "host": self.bmc_ip,
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
    def ssh_cmd(self,command):
        ssh_args = (
            "-o ServerAliveInterval=300 -o StrictHostKeyChecking=no"
            + " -o UserKnownHostsFile=/dev/null"
            + " -o LogLevel=error -o ConnectTimeout=30 -p 22"
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
            + "{user}@{host} '{commands}'"
        )
        return_code,output = self.system_run_command(command.format(**data))
        return return_code, output
    def system_run_command(self, cmd):
        self.logger.info(f"CMD: {cmd}")
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
        )
        full_output = proc.stdout.decode("utf-8", _UNI_ERR_RESP)
        if proc.stderr is not None:
            full_error = proc.stderr.decode("utf-8", _UNI_ERR_RESP)
        else:
            full_error = ""
        return proc.returncode, "%s%s".strip('\n\t') % (full_output, full_error)
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


class FailSafe(Remote):
    def __init__(self,scp_instance_0,scp_instance_1,atf_instance,cpu_instance,bmc_instance, bmc_ip,host, username='root', password='root',timeout=600):
        super().__init__(scp_instance_0,scp_instance_1,atf_instance,cpu_instance,bmc_instance, bmc_ip,host, username, password,timeout)
    def Set_Up_ATF_Boot_Failure_Normal_Config(self): 
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power off")
        cmd="gpiotool --set-data-low 226"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x1101F0"
        self.bmc_ssh_cmd(cmd)
        cmd="gpiotool --set-data-high 226"
        self.bmc_ssh_cmd(cmd)
        sleep(60)
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power on")
    
    def Set_Up_ATF_Boot_Failure_Normal_Config_Last_Know(self): 
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power off")
        cmd="gpiotool --set-data-low 226"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x1101F0"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x1001F0"
        self.bmc_ssh_cmd(cmd)
        cmd="gpiotool --set-data-high 226"
        self.bmc_ssh_cmd(cmd)
        sleep(60)
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power on")
    
    def Set_Up_UEFI_Boot_Failure_Normal_Config(self):
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power off")
        cmd="gpiotool --set-data-low 226"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x1101F8"
        self.bmc_ssh_cmd(cmd)
        cmd="gpiotool --set-data-high 226"
        self.bmc_ssh_cmd(cmd)
        sleep(60)
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power on")
    
    
    def Set_Up_UEFI_Boot_Failure_Normal_Config_Last_Know(self): 
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power off")
        cmd="gpiotool --set-data-low 226"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x1101F8"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x1001F8"
        self.bmc_ssh_cmd(cmd)
        cmd="gpiotool --set-data-high 226"
        self.bmc_ssh_cmd(cmd)
        sleep(60)
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power on")
    
    
    def Set_Up_PMpro_Boot_Failure_Normal_Config(self):
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power off")
        cmd="gpiotool --set-data-low 226"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x114068"
        self.bmc_ssh_cmd(cmd)
        cmd="gpiotool --set-data-high 226"
        self.bmc_ssh_cmd(cmd)
        sleep(60)
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power on")
    def Set_Up_OS_Boot_Failure(self):
        if not self.is_cpu_live():
            print ("OS deal")
            return 
        self.ssh_cmd('echo 1 > /proc/sys/kernel/sysrq')
        self.ssh_cmd('echo c > /proc/sysrq-trigger')
        return 
    
    def Set_Up_UEFI_Boot_Failure_Normal_Config_Last_Know(self): 
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power off")
        cmd="gpiotool --set-data-low 226"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x114068"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -s 0x1 -o 0x104068"
        self.bmc_ssh_cmd(cmd)
        cmd="gpiotool --set-data-high 226"
        self.bmc_ssh_cmd(cmd)
        sleep(60)
        self.system_run_command(f"ipmitool -H {self.bmc_ip} -U ADMIN -P ADMIN -I lanplus chassis power on")
    
    def Clear_NVparam(self):
        cmd="gpiotool --set-data-low 226"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -c -o 0x110000"
        self.bmc_ssh_cmd(cmd)
        cmd="nvparm -c -o 0x100000"
        self.bmc_ssh_cmd(cmd)
        cmd="gpiotool --set-data-high 226"
        self.bmc_ssh_cmd(cmd)
    
    def Check_ATF_Failsafe(self):
        print ("Start checking ATF failsafe: ATF boot failure with normal configuration and last known configuration")
        self.Set_Up_ATF_Boot_Failure_Normal_Config()
        scp_child.expect("SMpro Runtime Firmware v.+ - build \d+", timeout=300)
        start = time.time()
        scp_child.expect("ERR: Secure WDT triggered", timeout=1800)
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)
        print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
        
        sleep(300)
        self.Clear_NVparam()
        if self.is_cpu_live():
            print ("CPU boot to OS successfully")
        else:
            print ("CPU fail to OS")
        print ("Start checking ATF failsafe: ATF boot failure with normal configuration and last known configuration")
        self.Set_Up_ATF_Boot_Failure_Normal_Config_Last_Know()
        for i in range(3):
            print ("start at index {i} ")
            scp_child.expect("SMpro Runtime Firmware v.+ - build \d+", timeout=300)
            start = time.time()
            scp_child.expect("ERR: Secure WDT triggered", timeout=1800)
            end = time.time()
            hours, rem = divmod(end-start, 3600)
            minutes, seconds = divmod(rem, 60)
            print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
        self.Clear_NVparam()
        if self.is_cpu_live():
            print ("CPU boot to OS successfully")
        else:
            print ("CPU fail to OS")
    def Check_UEFI_Failsafe(self):
        print ("Start checking UEFI failsafe: UEFI boot failure with normal configuration")
        self.Set_Up_UEFI_Boot_Failure_Normal_Config()
        atf_child.expect("BL31: Image v.+", timeout=300)
        start = time.time()
        atf_child.expect("NS Watchdog expired.+", timeout=1800)
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)
        print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
        
        sleep(300)
        self.Clear_NVparam()
        if self.is_cpu_live():
            print ("CPU boot to OS successfully")
        else:
            print ("CPU fail to OS")
        print ("Start checking UEFI failsafe: UEFI boot failure with normal configuration and last known configuration")
        self.Set_Up_UEFI_Boot_Failure_Normal_Config_Last_Know()
        for i in range(3):
            print (f"start at index {i} ")
            atf_child.expect("BL31: Image v.+", timeout=300)
            start = time.time()
            atf_child.expect("NS Watchdog expired.+", timeout=1800)
            end = time.time()
            hours, rem = divmod(end-start, 3600)
            minutes, seconds = divmod(rem, 60)
            print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
        self.Clear_NVparam()
        if self.is_cpu_live():
            print ("CPU boot to OS successfully")
        else:
            print ("CPU fail to OS")
    def Check_Pmpro_Failsafe(self):
        print ("Start checking PMPRO failsafe: PMPro socket 0 boot failure with normal configuration")
        Set_Up_ATF_Boot_Failure_Normal_Config()
        scp_child.expect("SMpro Runtime Firmware v.+ - build \d+", timeout=300)
        start = time.time()
        scp_child.expect("ERR: Secure WDT triggered", timeout=1800)
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)
        print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
        
        sleep(300)
        self.Clear_NVparam()
        if self.is_cpu_live():
            print ("CPU boot to OS successfully")
        else:
            print ("CPU fail to OS")
        print ("Start checking PMPRO failsafe: PMPro socket 0 boot failure with normal configuration and last known configuration")
        Set_Up_ATF_Boot_Failure_Normal_Config_Last_Know()
        for i in range(3):
            print ("start at index {i} ")
            scp_child.expect("SMpro Runtime Firmware v.+ - build \d+", timeout=300)
            start = time.time()
            scp_child.expect("ERR: Secure WDT triggered", timeout=1800)
            end = time.time()
            hours, rem = divmod(end-start, 3600)
            minutes, seconds = divmod(rem, 60)
            print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
        self.Clear_NVparam()   
        if self.is_cpu_live():
            print ("CPU boot to OS successfully")
        else:
            print ("CPU fail to OS")
            
    def Check_OS_Failure_AT_OS(self):
        print ("Start checking OS Failure")
        if not self.is_cpu_live():
            print ("OS deal")
            return 
        self.Set_Up_OS_Boot_Failure()
        #atf_child.expect("BL31: Image v.+", timeout=300)
        start = time.time()
        #atf_child.expect("NS Watchdog expired.+", timeout=1800)
        scp_child.expect("SMpro Runtime Firmware v.+ - build \d+", timeout=900)
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)
        print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
        if self.is_cpu_live():
            print ("CPU boot to OS successfully")
        else:
            print ("CPU fail to OS")
    def Check_OS_Failure(self):
        print ("Start checking OS Failure")
        #if not self.is_cpu_live():
        #    print ("OS deal")
        #    return 
        #self.Set_Up_OS_Boot_Failure()
        os_child.expect("EFI stub: Booting Linux Kernel", timeout=900)
        start = time.time()
        atf_child.expect("NS Watchdog expired.+", timeout=1800)
        #scp_child.expect("SMpro Runtime Firmware v.+ - build \d+", timeout=900)
        end = time.time()
        hours, rem = divmod(end-start, 3600)
        minutes, seconds = divmod(rem, 60)
        print("WDT timeout result {:0>2}:{:0>2}:{:05.2f}".format(int(hours),int(minutes),seconds))
        #if self.is_cpu_live():
        #    print ("CPU boot to OS successfully")
        #else:
        #    print ("CPU fail to OS")
def is_valid_ip(ip):
    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$")
    is_ip= pat.match(ip)
    if is_ip:
        return True 
    else:
        return False
        
def main():
    parser = argparse.ArgumentParser(description='check FailSafe')
    parser.add_argument('--host', help='IP host of test CPU',type=str, default='', required=True)
    parser.add_argument('--bmc_ip', help='IP host of test BMC',type=str, default='', required=True)
    parser.add_argument('--component', help='select component to check',type=str, default='', required=True)
    parser.add_argument('--username', help='username login OS of CPU',type=str,default='root')
    parser.add_argument('--password', help='password to login test system',type=str,default='root')
    parser.add_argument('--time_login_sut', help='timeout try to login to CPU OS',type=int, default=600)
    parser.add_argument('--config_file', help='file configure of SUT',type=str, default='sut_tpm.json' )
    args = vars(parser.parse_args())
    host=args['host']
    bmc_ip=args['bmc_ip']
    username=args['username']
    password=args['password']
    time_out=args['time_login_sut']
    component=args['component']
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
    filename_date = 'failsafe_log_'+timestr+".txt"    
    FailSafe_obj=FailSafe(scp_0,scp_1, atf, cpu, bmc,bmc_ip,host, username=username, password=password,timeout=time_out)
    FailSafe_obj.prepare_sut()
    time.sleep(30)
    FailSafe_obj.connect_console()
    component=component.lower()
    if component == "all":
        FailSafe_obj.Check_UEFI_Failsafe()
        time.sleep(30)
        FailSafe_obj.Check_ATF_Failsafe()
        time.sleep(30)
        FailSafe_obj.Check_Pmpro_Failsafe()
    elif component =="pmpro":
        FailSafe_obj.Check_Pmpro_Failsafe()
    elif component =="atf":
        FailSafe_obj.Check_ATF_Failsafe()
    elif component=="uefi":
        FailSafe_obj.Check_UEFI_Failsafe()
    elif component=="os":
        FailSafe_obj.Check_OS_Failure()
    else:
        print ("do not support check component")
    
    FailSafe_obj.close_console(filename_date)
if  __name__ == '__main__':
    main()
