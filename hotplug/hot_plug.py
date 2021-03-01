#!/usr/bin/python3
import subprocess
import json 
import re 
import pprint 
import logging
import argparse
import os 
import shutil
import sys 
import datetime 
from nose import tools
from nose.tools import assert_equal
from nose.tools import assert_not_equal
import time
#logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',level=logging.DEBUG)
logging.basicConfig(format='%(levelname)s - %(message)s',level=logging.DEBUG)


slot_pcie={       
        '6'   :"0002:00:01.0" , 
        '7'   :"0002:00:03.0" , 
        '2'   :"0002:00:05.0" ,
        '3'   :"0002:00:07.0" ,
        '0'   :"0003:00:01.0" ,
        '1'   :"0003:00:03.0" ,
        '4'   :"0003:00:05.0" ,
        '5'   :"0003:00:07.0" ,
        '20'   :"0006:00:01.0" , 
        '21'   :"0006:00:02.0" ,
        '22'   :"0006:00:03.0" , 
        '23'   :"0006:00:04.0" , 
        '18'   :"0008:00:05.0" ,
        '19'   :"0008:00:07.0" ,
        '16'   :"0009:00:01.0" ,
        '17'   :"0009:00:03.0" ,
        '10'   :"000a:00:03.0" ,
        '11'   :"000a:00:01.0" ,
        '14'   :"000a:00:07.0" ,
        '15'   :"000a:00:05.0" ,
        '12'   :"000b:00:03.0" ,
        '13'   :"000b:00:01.0" ,
        '8'   :"000b:00:07.0" ,
        '9'   :"000b:00:05.0" ,
        'Onboard_CN1'   :"0005:00:05.0" ,
        'Onboard_CN2'   :"0005:00:07.0" ,
         'riser2_CN1'   :"0005:00:01.0" ,
         'riser2_CN2'   :"0000:00:01.0" ,
         'riser2_CN3'   :"0004:00:05.0" ,
         'riser1_CN1'   :"0009:00:05.0" ,
         'riser1_CN2'   :"0007:00:03.0" ,
         'riser1_CN3'   :"0007:00:01.0" ,
         'riser3_CN1'   :"0006:00:01.0" ,
         'riser3_CN2'   :"0008:00:01.0"
     }  

class HotPlug:
    def __init__(self,slot,action,debug,do_activity_task,led_action):
        self.slot_data=slot_pcie
        self.action=action
        self.check_slot=""
        self.path=""
        self.do_activity_task=do_activity_task
        self.debug=debug
        self.logger = logging.getLogger("Hot_Plug")
        self.logger.setLevel(logging.DEBUG)
        self.led_action=led_action
        
        self.debug_file=""
        self.storage_device=""
        
        self.parent_port=""
        self.device_port=""
        self.validate_slot(slot)
        self.device_name=""
        self.os_disk=""
        
        self.parent_port_vvv=""
        self.device_port_vvv=""
        
        #parent AER 
        self.parent_aer=dict()
        self.device_aer=dict()
        
        self.device_console_log="/dev/ttyAMA0"
        self.clear_log_dir=False
        self.data_root='/home/hot_plug'
        timestr = time.strftime("%Y%m%d-%H%M%S")
        self.target=f"/mnt/{timestr}"
        self.data_compare=f"{self.data_root}/{timestr}"
        self.prepare_data_test()
    def __del__(self):
        """ Post Section for TestNVMe. """
        if self.clear_log_dir is True:
            shutil.rmtree(self.target, ignore_errors=True)
            shutil.rmtree(self.data_compare, ignore_errors=True)
    def prepare_data_test(self):
        """ prepare_data_test.
            - Args:
                - None
            - Returns:
                - None
        """
        if self.clear_log_dir is True:
            shutil.rmtree(self.self.data_compare, ignore_errors=True)
        if not os.path.exists(self.data_root):
            os.makedirs(self.data_root)  
        if not os.path.exists(self.data_compare):
            os.makedirs(self.data_compare)        
        if not os.path.exists(self.target):
            os.makedirs(self.target)       
    def validate_pci_device_available(self):
        """ Validate underlaying device belogs to pci subsystem.
            - Args: 
                - None
            - Returns:
                - None
        """
        device=self.device_aer["device_name"]
        cmd = "find /sys/devices -name \\*" + device + " | grep -i pci"
        err = subprocess.call(cmd, shell=True)
        assert_equal(err, 0, "ERROR : device is not available")
    def validate_pci_device_not_available(self):
        """ Validate underlaying device belogs to pci subsystem.
            - Args:
                - None
            - Returns:
                - None
        """
        device=self.device_aer["device_name"]
        cmd = "find /sys/devices -name \\*" + device + " | grep -i pci"
        err = subprocess.call(cmd, shell=True)
        assert_not_equal(err, 0, "ERROR : device is available")
        
    def get_storage_device(self):
        self.detect_os_disk()
        cmd="find /sys/devices/ -name 'nvme[[:digit:]]*n[[:digit:]]' | grep -v 'virtual' | cut -d '/' -f 9"
        rc, nvme_device = self.linux_cmd(cmd)
        nvme_devices = nvme_device.splitlines()
        self.storage_device = self.remove_root_disk_from_list(
            nvme_devices
        )
    def list_to_string(self, data):
        str = ''
        separate = ':/dev/'
        try:
            str = separate.join(data)
            str = '/dev/' + str
        except (AttributeError):
            str = "Can not join string:  %s" % data
            raise AttributeError(str)
        return str
    def detect_group_port(self):
        cmd=f"find /sys/kernel/iommu_groups/ -type l | grep {self.device_port}"
        rc,data=self.linux_cmd(cmd)
        if rc ==0:
            self.group=data.split('/')[4]
            self.logger.info(f"group port of device: {data}")
            return 0 
        else:
            self.logger.error(f"can not find group port of device {self.device_port}")
            assert_equal(rc,0,f"can not find group port of device {self.device_port}")
            #return 1 
    def run_fio_without_test_device(self):
        self.get_storage_device()
        device=self.device_aer["device_name"]
        self.storage_device.remove(device)
        remainder_devices=self.list_to_string(self.storage_device)
        cmd=f"fio --filename={remainder_devices} --direct=1 --do_verify=1 --verify='md5' --rw=randrw --bs=128k --ioengine=libaio --iodepth=64 --runtime=120 --numjobs=1 --time_based --group_reporting --name=hot_plug_nvme --eta-newline=1"
        rc,data=self.linux_cmd(cmd)
        if rc ==0:
            self.logger.info(f"FIO runs successfully ")
            self.logger.info(data)
        else:
            self.logger.error(f"FIO runs failed ")
            self.logger.error(data)
            
    def run_fio_with_test_device(self):
        self.get_storage_device()
        remainder_devices=self.list_to_string(self.storage_device)
        cmd=f"fio --filename={remainder_devices} --direct=1 --do_verify=1 --verify='md5' --rw=randrw --bs=128k --ioengine=libaio --iodepth=64 --runtime=120 --numjobs=1 --time_based --group_reporting --name=hot_plug_nvme --eta-newline=1"
        rc,data=self.linux_cmd(cmd)
        if rc ==0:
            self.logger.info(f"FIO runs successfully ")
            self.logger.info(data)
        else:
            self.logger.error(f"FIO runs failed ")
            self.logger.error(data)
            
    def run_fio_only_test_device(self):
        device=self.device_aer["device_name"]
        cmd=f"fio --filename=/dev/{device} --direct=1 --do_verify=1 --verify='md5' --rw=randrw --bs=128k --ioengine=libaio --iodepth=64 --runtime=120 --numjobs=1 --time_based --group_reporting --name=hot_plug_nvme --eta-newline=1"
        rc,data=self.linux_cmd(cmd)
        if rc ==0:
            self.logger.info(f"FIO runs successfully ")
            self.logger.info(data)
        else:
            self.logger.error(f"FIO runs failed ")
            self.logger.error(data)        
            
    def _write_console_log(self, msg):
        data=f"echo {msg} >> {self.device_console_log}"
        rc, data = self.linux_cmd(data)
        if rc !=0: 
            self.logger.error(f"fail to write msg to kernel console log")
    
    
        # @timer
    def detect_os_disk(self):
        """ Returns a disk root and a list contains partitions \
            related to root file system.
        """
        part_root = 0
        index_disk = 0
        device_name = ''
        os_disk = ''
        os_disk_part = list()
        disks_with_boot_partitions = 0
        command_find = 'lsblk'
        rc, data = self.linux_cmd(command_find)
        lsblk_list = data.splitlines()
        reference_list = ['/', '/boot/efi', '/boot', '/home', '[SWAP]']
        if len(lsblk_list) == 0:
            self.logger.error("no output data")
        else:
            for index in range(len(lsblk_list)):
                dataline = lsblk_list[index].strip().split()
                if dataline[len(dataline) - 1] == "disk":
                    device_name = dataline[0]
                    part_root = 0
                    index_disk = 1
                elif dataline[len(dataline) - 1] == "part":
                    part_is_mounted = lsblk_list[index].strip().split()[0]

                if dataline[len(dataline) - 2] == "part":
                    mountpoint = dataline[len(dataline) - 1].strip()
                    if mountpoint in reference_list:
                        part_root = 1
                        obj = re.search(r'(\w+)', dataline[0])
                        if obj:
                            os_disk_part.append(obj[1])
                elif dataline[len(dataline) - 2] == "lvm":
                    mountpoint = dataline[len(dataline) - 1].strip()
                    if mountpoint in reference_list:
                        part_root = 1
                        obj = re.search(r'(\w+)', part_is_mounted)
                        if obj:
                            os_disk_part.append(obj[1])

                if (part_root == 1) and (index_disk == 1):
                    disks_with_boot_partitions += 1
                    os_disk = device_name
                    part_root = 0
                    index_disk = 0

        if disks_with_boot_partitions != 1:
            raise Exception('FAIL: Detect OS boot disk was problem')
        self.logger.info(f"the OS root drive is {os_disk}")
        self.os_disk = os_disk
        return os_disk, list(dict.fromkeys(os_disk_part))

    def remove_root_disk_from_list(self, data):
        if isinstance(data, list):
            # root_disk, root_part = self.detect_os_disk()
            if self.os_disk in data:
                data.remove(self.os_disk)
            return data
        else:
            self.logger.error('FAIL: data: %s ', data)
            return data
            
    def linux_cmd(self, cmd):
        print(cmd)
        output=""
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True
        )
        full_output = proc.stdout.decode("utf-8", 'replace')
        if proc.returncode:
            output="%s_%s".strip('\n\t')%(proc.stderr,full_output)
        else:
            output=full_output.strip('\n\t')
        #print(output)
        return proc.returncode, output
    
    def validate_slot(self, slot):
        if str(slot) in self.slot_data:
            self.check_slot=slot
            self.parent_port=self.slot_data[slot]
        else:
            raise Exception (f"do not support check slot : {slot}")
            
    def _get_key_from_value(self, val):
        for key, value in self.slot_data.items():
            if val == value:
                return key
        return ""
        
    def prepare_data(self):
        path = os.getcwd()
        self.path=f"{path}/{self.check_slot}"
        if os.path.exists(self.path) and os.path.isdir(self.path):
            pass
        else:
            try:
                os.mkdir(self.path)
            except OSError:
                print ("Creation of the directory %s failed" % self.path)
            else:
                print ("Successfully created the directory %s " % self.path)
            
        self.path=f"{self.path}/{self.action}"
        if os.path.exists(self.path) and os.path.isdir(self.path):
           # shutil.rmtree(self.path)
           pass
        else:
            try:
                os.mkdir(self.path)
            except OSError:
                print ("Creation of the directory %s failed" % self.path)
            else:
                print ("Successfully created the directory %s " % self.path)
        date_time=datetime.datetime.now()
        date_time=str(date_time).replace("-","_").replace(" ","_").replace(":","_").replace(".","_")
        self.debug_file=f"{self.path}/debug_{date_time}.txt"
        self.logger.info(f"the filename debug is {self.debug_file}")
        self.create_file(self.debug_file)
        cmd="dmesg -C"
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("can not delete dmesg kernel")
            self.exit_hot_plug()
    
    def detect_available_slot(self):
        cmd="find /sys/devices/ -name 'nvme[[:digit:]]*n[[:digit:]]' | grep -v 'virtual'"
        rc, data =self.linux_cmd(cmd)
        if rc ==0:
            for line in data.splitlines():
                slot=self._get_key_from_value(line.split('/')[4])
                if len(slot) != 0:
                    self.logger.info (f"the slot is ready for test {slot}")
        else:
            self.logger.error(f"can not find slot data ")
    
    def verify_after_removal_parent_port(self):
        '''
            bridge port:
                find /sys/devices/ -name "000b:00:07.0" | grep -v 'smmu'
                lspci -s <parent_port> -vvv 
                riser_data_cmd=f"ls -l /sys/bus/pci/devices/ | grep '{bridge}' | grep -v '{bridge}$'"
            lshw -class storage -businfo | grep '<test_controller_port>'
            nvme list | grep <test_device>
            find /sys/devices/ -name 'nvme[[:digit:]]*n[[:digit:]]' | grep -v 'virtual' | grep '0003:04:00.0'
            
        '''
        cmd=f"lspci | grep -v '{self.parent_port}'"
        rc, parent_data = self.linux_cmd(cmd)
        if rc!=0: 
            self.logger.error(f"parent port: {self.parent_port} is removed out of lspci")
        else:
            self.logger.info(f"parent port: {self.parent_port} appears in results of lspci")
        
        cmd=f"find /sys/devices/ -name {self.parent_port} | grep -v 'smmu'"
        rc, parent_data = self.linux_cmd(cmd)
        if rc==0: 
            self.logger.info(f"parent port: {self.parent_port} is appeared")
        else:
            cmd=f"lspci -s {self.parent_port} -vvv"
            rc, data=self.linux_cmd(cmd)
            if rc !=0:
                self.logger.error(f"can not get information of parent port")
                self.exit_hot_plug()
            else:
                self.logger.info(data)
                
        cmd=f"ls -l /sys/bus/pci/devices/ | grep '{self.parent_port}' | grep -v '{self.parent_port}$'"
        rc, sysfs_crt = self.linux_cmd(cmd)
        if rc==0:
            self.logger.error(f"controller of test device have not removed")
            self.logger.error(sysfs_crt)
        else:
            self.logger.info(f"controller of test device is removed of /sys/bus/pci/devices/")
        
    def veify_after_removal_nvme(self):
        
        cmd=f"lshw -class storage -businfo | grep {self.device_port}"
        rc, businfo = self.linux_cmd(cmd)
        if rc==0:
            self.logger.error(f"controller of test device have not removed")
            self.logger.error(businfo)
        else:
            self.logger.info("businfo is removed out of lshw businfo")
            
        device=self.device_aer["device_name"]
        cmd=f"nvme list | grep {device}"
        rc, nvme_list = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.info("device is removed out of nvme list")
        else:
            self.logger.error("device is NOT removed out of nvme list")
            self.logger.error(f"return code: {rc}  data {nvme_list}")
        cmd=f"find /sys/devices/ -name 'nvme[[:digit:]]*n[[:digit:]]' | grep -v 'virtual' | grep {self.device_port}"
        rc, device_sysfs = self.linux_cmd(cmd)
        if rc!=0:
            self.logger.info("device is removed out of sysfs device ")
        else:
            self.logger.error("device is NOT removed out of sysfs device")
            self.logger.error(f"return code: {rc}  data {device_sysfs}")
        cmd=f"ls -l /sys/block/| grep {device}"
        rc, block_sysfs = self.linux_cmd(cmd)
        if rc!=0:
            self.logger.info("device is removed out of sysfs block device ")
        else:
            self.logger.error("device is NOT removed out of sysfs block device")
            self.logger.error(f"return code: {rc}  data {block_sysfs}")
        self.validate_pci_device_not_available()
        self.get_parent_inform()
    def do_graceful_removal(self):
        '''
            grep 0003:01:00 /sys/bus/pci/slots/*/address
        '''
        
        msg=f"SQA_checks_Hot_Plug_for_slot_{self.check_slot}_START"
        self._write_console_log(msg)
        self.logger.info(f"checking graceful_removal hot-plug at slot {self.check_slot}")
        self.get_parent_inform()
        self.detect_nvme_device()
        self.detect_group_port()
        if self.debug:
            self.get_debug_information()
        cmd=f"lspci -s {self.parent_port} -vvv"
        rc, parent_data_vvv = self.linux_cmd(cmd)
        if rc ==0:
            self.parent_data_vvv=parent_data_vvv
            self.write_log(parent_data_vvv)
        else:
            self.logger.error(f"can not get information of parent port before doing graceful_removal action")
            cmd=f"lspci | grep {slef.parent_port[0:4]}"
            rc, debug = self.linux_cmd(cmd)
            self.logger.info(debug)
            return 1
            
        cmd=f"lspci -s {self.device_port} -vvv"
        rc, device_data_vvv = self.linux_cmd(cmd)
        if rc ==0:
            self.device_data_vvv=device_data_vvv
            self.write_log(device_data_vvv)
        else:
            self.logger.error(f"can not get information of device port before doing graceful_removal")
            self.detect_available_slot()
            return 2     
        cmd=f"grep {self.device_port[:-2]} /sys/bus/pci/slots/*/address"
        rc, slot_data = self.linux_cmd(cmd)
        if rc ==0: 
            slot_sys=slot_data.split('/')[5]
            power_cmd=f"echo 0 > /sys/bus/pci/slots/{slot_sys}/power"
            rc, power_data = self.linux_cmd(power_cmd)
            if rc ==0:
                self.logger.info(f"do graceful_removal action for slot {self.device_port} successfully")
            else:
                self.logger.error(f"do graceful_removal action for slot {self.device_port} failed")
        else:
            self.logger.error(f"can not find the slot in sysfs of slot {self.check_slot}")
            return 0 
            
        self.logger.info("please do physically remove device out of system")
        self.logger.info("select Y to continue, otherwise it is exit")
        select_action = str(input())
        if select_action in ['y','Y','Yes','yes']:
            self.logger.info("START: verify data .............................")
            self.numpat(10)
            self.verify_after_removal_parent_port()
            self.veify_after_removal_nvme()
            self.logger.info("END: verify data .............................")
            self.numpat(10)
            choose=self._do_surprise_insertion()
            if choose:
                self.get_parent_inform()
                self.detect_nvme_device()
                self.detect_group_port()
                self._verify_surprise_insertion()
            else:
                self.exit_hot_plug()
        else:
            self.exit_hot_plug()
     
    def _verify_surprise_insertion(self):
        self.numpat(10)
        cmd="dmesg"
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("can not delete dmesg kernel")
            self.exit_hot_plug()
        else:
            self.logger.info(f"data from kernel message {data}")
        
        device=self.device_aer["device_name"]
        cmd=f"echo y | mkfs.ext4 /dev/{device}"
        
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("can not create file type for device")
            self.exit_hot_plug()
        else:
            self.logger.info(f"data:  {data}")
            
            
        cmd=f"mount /dev/{device} {self.target}"
        
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("can not mount device")
            self.exit_hot_plug()
        else:
            self.logger.info(f"data:  {data}")
        
        cmd=f"dd if=/dev/zero of={self.target}/create_file bs=1G count=50"
        
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("can not create file")
            self.exit_hot_plug()
        else:
            self.logger.info(f"data:  {data}")
        cmd=f"echo y | cp {self.target}/create_file {self.data_compare}"
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("can not read data from device")
            self.exit_hot_plug()
        else:
            self.logger.info(f"data:  {data}")
        
        cmd=f"cmp {self.target}/create_file {self.data_compare}/create_file"
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("error when comparing data")
            self.exit_hot_plug()
        else:
            self.logger.info(f"data:  {data}")
        
        cmd=f"diff {self.target}/create_file {self.data_compare}/create_file"
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("error when comparing data")
            self.exit_hot_plug()
        else:
            self.logger.info(f"data:  {data}")
        cmd=f"umount {self.target}"
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error("can not unmount device")
            self.exit_hot_plug()
        #self.nvme_reset_ctrl()
        self.get_smart_log()
        node=0
        if self.parent_port[0:4] in ["0000","0001","0002","0003","0004","0005"]:
            node=0 
        elif self.parent_port[0:4] in ["0006","0007","0008","0009","000a","000b"]:
            node=1
        else:
            self.logger.error("can not find cpu node of parent port {self.parent_port}")
            self.exit_hot_plug()
            
        cmd=f"numactl --cpunodebind={node} fio --filename=/dev/{device} --direct=1 --do_verify=1 --verify='md5' --rw=randrw --bs=128k --ioengine=libaio --iodepth=64 --runtime=120 --numjobs=1 --time_based --group_reporting --name=hot_plug_nvme_{device} --eta-newline=1"
        
        rc, data = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.error(f"can not run FIO successfully: {data}")
            self.exit_hot_plug()
        else:
            self.logger.info(f"data:  {data}")
        self.numpat(10)
    
    def split_multiline_string_to_dict(self, 
    string, key_val_delim=' ',
    ):
        r"""
        Split a string into a dictionary and return it.

        This function is the complement to join_dict.

        Description of argument(s):
        string                          The string to be split into a dictionary.
                                        The string must have the proper delimiters
                                        in it.  A string created by join_dict
                                        would qualify.

        key_val_delim                   The delimiter to be used to separate
                                        keys/values in the input string.

        """

        result_dict = {}

        raw_keys_values = string.split("\n")
        for key_value in raw_keys_values:
            key_value_list = key_value.split(key_val_delim)
            try:
                result_dict[key_value_list[0].strip()] = key_value_list[1].strip()
            except IndexError:
                result_dict[key_value_list[0].strip()] = ""

        return result_dict

       
     
    def get_parent_inform(self):
        '''
            aer_dev_correctable
            aer_dev_fatal
            aer_dev_nonfatal
            /sys/devices/pci0003:00/0003:00:07.0
        '''
        cmd=f"lspci -s {self.parent_port} -vvv"
        rc, parent_data_vvv = self.linux_cmd(cmd)
        if rc ==0:
            self.parent_data_vvv=parent_data_vvv
            #self.write_log(parent_data_vvv)
        else:
            self.logger.error(f"can not get information of parent port before doing graceful_removal action")
            cmd=f"lspci | grep {slef.parent_port[0:4]}"
            rc, debug = self.linux_cmd(cmd)
            self.logger.info(debug)
            self.exit_hot_plug()
        
        cmd=f"find /sys/devices/ -name {self.parent_port} | grep -v smmu"
        parent_infor_tmp={
                        "aer_dev_correctable":"",
                        "aer_dev_fatal":"",
                        "aer_dev_nonfatal":""
                         }
                         
        rc, ctr_parent_sysfs = self.linux_cmd(cmd)
        cmd_aer_dev_correctable=f"cat {ctr_parent_sysfs}/aer_dev_correctable"
        rc, aer_data = self.linux_cmd(cmd_aer_dev_correctable)
        assert_equal(rc,0,'can not get aer_dev_correctable ') 
        aer=self.split_multiline_string_to_dict(aer_data)
        #with open(cmd_aer_dev_correctable) as data_file:
        #    aer = json.load(data_file)
        parent_infor_tmp["aer_dev_correctable"]=aer
        cmd_aer_dev_fatal=f"cat {ctr_parent_sysfs}/aer_dev_fatal"
        rc, aer_data = self.linux_cmd(cmd_aer_dev_fatal)
        assert_equal(rc,0,'can not get aer_dev_fatal') 
        aer=self.split_multiline_string_to_dict(aer_data)
        #with open(cmd_aer_dev_fatal) as data_file:
        #    aer = json.load(data_file)
        parent_infor_tmp["aer_dev_fatal"]=aer
        
        cmd_aer_dev_nonfatal=f"cat {ctr_parent_sysfs}/aer_dev_nonfatal"
        rc, aer_data = self.linux_cmd(cmd_aer_dev_nonfatal)
        assert_equal(rc,0,'can not get aer_dev_fatal') 
        aer=self.split_multiline_string_to_dict(aer_data)
        #with open(cmd_aer_dev_nonfatal) as data_file:
        #    aer = json.load(data_file)
        parent_infor_tmp["aer_dev_nonfatal"]=aer
        self.parent_aer=parent_infor_tmp
        print ('AER data')
        pprint.pprint(self.parent_aer)
        
    def detect_nvme_device(self):
        '''
            find /sys/devices/ -name 'nvme[[:digit:]]*n[[:digit:]]' | grep -v 'virtual' | grep '0003:04:00.0'
            /sys/devices/pci0003:00/0003:00:07.0/0003:04:00.0/nvme/nvme1/nvme1n1
            find /sys/devices/ -name '0003:04:00.0' | grep -v 'smmu'
            /sys/devices/pci0003:00/0003:00:07.0/0003:04:00.0
            
        '''
        nvme_infor_tmp={
                        "device_name":"",
                        "aer_dev_correctable":"",
                        "aer_dev_fatal":"",
                        "aer_dev_nonfatal":""
                         }
        cmd_find_device = (
            "find /sys/devices/ -name 'nvme[[:digit:]]*n[[:digit:]]' "
            + "| grep -v 'virtual' | grep -i %s "
            % self.parent_port
        )
        #print (self.parent_port)
        rc, nvme_device = self.linux_cmd(cmd_find_device)
        if rc ==0:
            nvme_infor_tmp['device_name']=nvme_device.split('/')[-1]
            self.device_name=nvme_device.split('/')[-1].strip()
            nvme_device = nvme_device.split('/')[5].strip()
        else:
            if self.action =="sr":
                self.logger.info(f"do surprise_removal successfully")
                return 0
            self.logger.error(f" do not find device in parent port {self.parent_port}")
            self.detect_available_slot()    
            self.exit_hot_plug() 
        self.device_port=nvme_device
        self.device_aer=nvme_infor_tmp
        cmd=f"lspci -s {self.device_port} -vvv"
        rc,data=self.linux_cmd(cmd)
        #print(data) 
    def create_file(self,fileName=''):
        if len(fileName)!=0:
            f = open(fileName, "w+")
            f.close()
        else:
            f = open(self.debug_file, "w+")
            f.close()
    
    def write_data(self,file, msg, mode='a+'):
        try:
            print (file)
            print (msg)
            f = open(file, mode)
            f.write(msg)
            f.write("\n")
            f.close()
            return 1
        except Exception as e:
            self.logger.error('Can not write data to file ')
    
    def write_log(self, msg, mode='a+'):
        try:
            f = open(self.debug_file, mode)
            f.write(msg)
            f.close()
            return 1
        except Exception as e:
            self.logger.error('Can not write data to file ')
    def remove_file(self):
        try:
            os.system("rm -rf %s" % self.debug_file)
        except Exception as e:
            pass
            
    def do_activity_task(self):
        cmd=f"dd if=/dev/zero of=/dev/{self.device_name} bs=1G count=100"
        rc,data=self.linux_cmd(cmd)
        self.logger.info(f" return code {rc}    data    {data}")
    
    def get_debug_information(self):
        self.remove_file()
        self.create_file()
        cmd='lspci -tvvv'  
        rc, data= self.linux_cmd(cmd)
        self.write_log(data)
        cmd="lspci -vvv"
        rc, data= self.linux_cmd(cmd)
        self.write_log(data)
        cmd="lspci"
        rc, data= self.linux_cmd(cmd)
        self.write_log(data)
           
            
    def do_surprise_removal(self):
        msg=f"SQA_checks_Hot_Plug_for_slot_{self.check_slot}_START"
        self._write_console_log(msg)
        if self.debug:
            self.get_debug_information()
        self.get_parent_inform()
        self.detect_nvme_device()
        self.detect_group_port()
        self._do_surprise_removal()
        choose=self._do_surprise_insertion()
        if choose:
            self.get_parent_inform()
            self.detect_nvme_device()
            self.detect_group_port()
            self._verify_surprise_insertion()
        else:
            self.exit_hot_plug()
    def _do_surprise_removal(self):
        print("do you check surprise removal action" )
        self.logger.info("select Y to continue, otherwise it is exit")
        select_action = str(input())
        if select_action in ['y','Y','Yes','yes']:
            self.verify_after_removal_parent_port()
            self.veify_after_removal_nvme()
    
    def _do_surprise_insertion(self):
        print("do you check surprise insertion action" )
        self.logger.info("select Y to continue, otherwise it is exit")
        select_action = str(input())
        choose=False 
        if select_action in ['y','Y','Yes','yes']:
            #self.detect_nvme_device()
            #pass
            #self.get_parent_inform()
            #self.detect_nvme_device()
            #self.detect_group_port()
            #self._verify_surprise_insertion()
            choose=True 
            return choose
        else:
            self.exit_hot_plug()
    def verify_after_insert_parent_port(self):
        '''
            bridge port:
                find /sys/devices/ -name "000b:00:07.0" | grep -v 'smmu'
                lspci -s <parent_port> -vvv 
                riser_data_cmd=f"ls -l /sys/bus/pci/devices/ | grep '{bridge}' | grep -v '{bridge}$'"
            lshw -class storage -businfo | grep '<test_controller_port>'
            nvme list | grep <test_device>
            find /sys/devices/ -name 'nvme[[:digit:]]*n[[:digit:]]' | grep -v 'virtual' | grep '0003:04:00.0'
            
        '''
        cmd=f"lspci | grep -v '{self.parent_port}'"
        rc, parent_data = self.linux_cmd(cmd)
        if rc!=0: 
            self.logger.error(f"parent port: {self.parent_port} is removed out of lspci")
        else:
            self.logger.info(f"parent port: {self.parent_port} appears in results of lspci")
        
        cmd=f"find /sys/devices/ -name {self.parent_port} | grep -v 'smmu'"
        rc, parent_data = self.linux_cmd(cmd)
        if rc!=0: 
            self.logger.error(f"parent port: {self.parent_port} is removed")
        else:
            cmd=f"lspci -s {self.parent_port} -vvv"
            rc, data=self.linux_cmd(cmd)
            if rc !=0:
                self.logger.error(f"can not get information of parent port")
                self.exit_hot_plug()
            else:
                self.logger.info(data)
                
        cmd=f"ls -l /sys/bus/pci/devices/ | grep '{self.parent_port}' | grep -v '{self.parent_port}$'"
        rc, sysfs_crt = self.linux_cmd(cmd)
        if rc==0:
            self.logger.info(f"controller of test device appears in /sys/bus/pci/devices/")
            self.logger.info(sysfs_crt)
        else:
            self.logger.error(f"controller of test device is removed of /sys/bus/pci/devices/")
            
    def veify_after_insert_nvme(self):
        cmd=f"lshw -class storage -businfo | grep {self.device_port}"
        rc, businfo = self.linux_cmd(cmd)
        if rc==0:
            self.logger.error(f"controller of test device have not removed")
            self.logger.error(businfo)
        else:
            self.logger.info("businfo is removed out of lshw businfo")
            
        device=self.device_aer["device_name"]
        cmd=f"nvme list | grep {device}"
        rc, nvme_list = self.linux_cmd(cmd)
        if rc !=0:
            self.logger.info("device is removed out of nvme list")
        else:
            self.logger.error("device is NOT removed out of nvme list")
            self.logger.error(f"return code: {rc}  data {nvme_list}")
        cmd=f"find /sys/devices/ -name 'nvme[[:digit:]]*n[[:digit:]]' | grep -v 'virtual' | grep {self.device_port}"
        rc, device_sysfs = self.linux_cmd(cmd)
        if rc!=0:
            self.logger.info("device is removed out of sysfs device ")
        else:
            self.logger.error("device is NOT removed out of sysfs device")
            self.logger.error(f"return code: {rc}  data {device_sysfs}")
        cmd=f"ls -l /sys/block/| grep {device}"
        rc, block_sysfs = self.linux_cmd(cmd)
        if rc!=0:
            self.logger.info("device is removed out of sysfs block device ")
        else:
            self.logger.error("device is NOT removed out of sysfs block device")
            self.logger.error(f"return code: {rc}  data {block_sysfs}")
            
    def do_surprise_insertion(self):
        msg=f"SQA_checks_Hot_Plug_for_slot_{self.check_slot}_START"
        self._write_console_log(msg)
        if self.debug:
            self.get_debug_information()
        self.get_parent_inform()
        choose=self._do_surprise_insertion()
        if choose:
            self.get_parent_inform()
            self.detect_nvme_device()
            self.detect_group_port()
            #self._verify_surprise_insertion()
        else:
            self.exit_hot_plug()
    def run_parallel(self):
        msg=f"SQA_checks_Hot_Plug_for_slot_{self.check_slot}_START"
        self._write_console_log(msg)
        self.get_parent_inform()
        self.detect_nvme_device()
        self.detect_group_port()
        if self.do_activity_task == 'wo':
             self.run_fio_without_test_device()
        elif self.do_activity_task == 'cs':
             self.run_fio_with_test_device()
        elif self.do_activity_task == 'only':
           self.run_fio_only_test_device()
        else:
            self.logger.error(f"do not support the action parallel {self.do_activity_task}")
            self.exit_hot_plug()
        msg=f"SQA_checks_Hot_Plug_for_slot_{self.check_slot}_END"
        self._write_console_log(msg)
    def numpat(self,n): 
        # initialising starting number  
        num = 1
    
        # outer loop to handle number of rows 
        for i in range(0, n): 
        
            # re assigning num 
            num = 1
        
            # inner loop to handle number of columns 
                # values changing acc. to outer loop 
            for j in range(0, i+1): 
            
                    # printing number 
                print(num, end=" ") 
            
                # incrementing number at each column 
                num = num + 1
        
            # ending line after each row 
            print("\r")     
    def run(self):
        self.logger.info(f"we are checking the slot:    {self.check_slot}")
        self.prepare_data()
        if self.action =="gr":
            self.do_graceful_removal()
        elif self.action =="sr":
            self.do_surprise_removal()
        elif self.action =="si":
            self.do_surprise_insertion()
        else:
            self.logger.error(f"do not support the action {self.action}")
        msg=f"SQA_checks_Hot_Plug_for_slot_{self.check_slot}_END"
        self._write_console_log(msg)
        return 0 
        
    def nvme_reset_ctrl(self):
        """ Wrapper for nvme reset command.
            - Args:
                - None:
            - Returns:
                - None
        """
        device=self.device_aer["device_name"]
        #nvme_reset_cmd = "nvme reset /dev/" + device.replace('n1','')
        nvme_reset_cmd = "nvme reset /dev/" + device[:-4]
        err = subprocess.call(nvme_reset_cmd,
                              shell=True,
                              stdout=subprocess.PIPE,
                              encoding='utf-8')
        assert_equal(err, 0, "ERROR : nvme reset failed")
        time.sleep(5)
        #rescan_cmd = "echo 1 > /sys/bus/pci/rescan"
        #proc = subprocess.Popen(rescan_cmd,
        #                        shell=True,
        #                        stdout=subprocess.PIPE,
        #                        stderr=subprocess.PIPE,
        #                        encoding='utf-8')
        #time.sleep(5)
        #assert_equal(proc.wait(), 0, "ERROR : pci rescan failed")
        
    def get_smart_log(self):
        """ Wrapper for nvme smart-log command.
            - Args:
                - nsid : namespace id to get smart log from.
            - Returns:
                - 0 on success, error code on failure.
        """
        ctl=self.device_aer["device_name"]
        smart_log_cmd = "nvme smart-log /dev/" + ctl.replace('n1','')
        print(smart_log_cmd)
        proc = subprocess.Popen(smart_log_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                                encoding='utf-8')
        err = proc.wait()
        assert_equal(err, 0, "ERROR : nvme smart log failed")

        for line in proc.stdout:
            if "data_units_read" in line:
                data_units_read = \
                    line.replace(",", "", 1)
            if "data_units_written" in line:
                data_units_written = \
                    line.replace(",", "", 1)
            if "host_read_commands" in line:
                host_read_commands = \
                    line.replace(",", "", 1)
            if "host_write_commands" in line:
                host_write_commands = \
                    line.replace(",", "", 1)

        print("data_units_read " + data_units_read)
        print("data_units_written " + data_units_written)
        print("host_read_commands " + host_read_commands)
        print("host_write_commands " + host_write_commands)
        return err    
    def check_led_attenion(self):
        msg=f"SQA_checks_Hot_Plug_for_slot_{self.check_slot}_START"
        self._write_console_log(msg)
        self.logger.info(f"checking check_led_attenion hot-plug at slot {self.check_slot}")
        self.get_parent_inform()
        self.detect_nvme_device()
        device=self.device_aer["device_name"]
        #nvme10n1
        if len(device)==8:
            ctr=6
        else:
            ctr=5
        device=device[0:ctr]
        cmd=f"altra-ledctl {self.led_action}=/dev/{device}"
        rc, data= self.linux_cmd(cmd)
        print(f"data: {data}")
        print (f"return code {rc}")
    def exit_hot_plug(self,msg=""):
        sys.stderr.write(msg)
        sys.stderr.flush()
        msg=f"SQA_checks_Hot_Plug_for_slot_{self.check_slot}_END"
        self._write_console_log(msg)
        sys.exit(2)
def main():
    parser = argparse.ArgumentParser(description='check PCIe Hot Plug')
    parser.add_argument('--slot', help='please select U2 NVMe slot',type=str, default='', required=True)
    parser.add_argument('--action', help='only support graceful_removal: gr, surprise_removal: sr, surprise_insertion:si',type=str,default='')
    parser.add_argument('--debug', help='enable debug information',type=bool, default=False)
    parser.add_argument('--do_activity_task', help='doing activites for test device',type=str, default='')
    parser.add_argument('--led_action', help='off: Turn off RED LED.fault: Turn on RED LED. locate: Blink at 1Hz RED LED. rebuild: Blink at 4Hz RED LED.',type=str, default='')
    args = vars(parser.parse_args())
    slot=args['slot']
    action=args['action']
    debug=args['debug']
    led_action=args['led_action']
    do_activity_task=args['do_activity_task']
    if len (action) !=0: 
        if action not in ["gr","sr", "si"]:
            sys.stderr.write("Error:  only support action graceful_removal,surprise_removal, surprise_insertion \n")
            sys.stderr.flush()
            sys.exit(1)
    all=False 
    if slot in ['all','ALL','All']:
        all=True 
    elif slot not in slot_pcie:
        sys.stderr.write(" do not support the slot \n")
        sys.stderr.flush()
        #sys.exit(2)
    if len(do_activity_task) !=0:
        if do_activity_task not in ['wo','only','cs']:
            sys.stderr.write(" do not support the do_activity_task \n")
            sys.stderr.flush()
            #sys.exit(3)
    if all:
        for slot_one in range(0,23):
            
            hot_plug_obj=HotPlug(str(slot_one),action,debug,do_activity_task,led_action)
            if len(led_action) !=0:
                hot_plug_obj.check_led_attenion()
            elif len(do_activity_task) ==0:
                hot_plug_obj.run()
            else:
                hot_plug_obj.run_parallel()
            hot_plug_obj.__del__()
            time.sleep(30)
    else: 
        hot_plug_obj=HotPlug(slot,action,debug,do_activity_task,led_action)
        if len(led_action) !=0:
            hot_plug_obj.check_led_attenion()
        elif len(do_activity_task) ==0:
            hot_plug_obj.run()
        else:
            hot_plug_obj.run_parallel()

if  __name__ == '__main__':
    main()
    
