from datetime import datetime
import os
import sys
import time
import pexpect


LINE_SEPARATOR = os.linesep
CONECTION_TYPE_TELNET = 1
CONECTION_TYPE_SOL = 2
CONECTION_TYPE_SSH = 3
CONECTION_TYPE_CONSOLE = 4

DELAY_BEFORE_SEND = 5
STR_LOGIN = "login:"
STR_PASSWD = "assword:"
TIMEOUT = 600

class Connection:
    def __init__(self,command,filename, is_connect):
        self.handle = None
        self.prompt = ["]#", "~#", "]$", "~>"]
        self.retry = 0
        self.is_telnet_or_sol=is_connect  # 0: unknown , 1 telnet, 2 sol 
        self.command=command
        self.delay = 3
        self.dir_logs=''
        self.file_name=filename
        self.create_file()
    
    
    def create_log_folder(self,directory='logs'):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        #cwd = os.getcwd()
        path = os.path.join(dir_path, directory)
        self.dir_logs=path
        if not os.path.isdir(path):
            try: 
                os.makedirs(path, exist_ok = True) 
                self._print_console("Directory '%s' created successfully" % directory) 
            except OSError as error: 
                self._print_error("Directory '%s' can not be created" % directory)
        else:
            pass
                
    def create_file(self):
        self.create_log_folder()
        self.file_name= self.dir_logs +"/" + self.file_name
        f = open(self.file_name, "w+")
        f.close()
        
        
    def write_file(self,file, msg, mode='a+'):
        try:
            f = open(file, mode)
            f.write(msg)
            f.close()
            return 1
        except Exception as e:
            self.logger.error(
                'Error on line {}, %s: %s'.format(sys.exc_info()[-1].tb_lineno)
                % (type(e).__name__, e)
            )
    
    def write_log(self, msg, mode='a+'):
        try:
            f = open(self.file_name, mode)
            f.write(msg)
            f.close()
            return 1
        except Exception as e:
            self.logger.error(
                'Error on line {}, %s: %s'.format(sys.exc_info()[-1].tb_lineno)
                % (type(e).__name__, e)
            )
    def remove_file(self, fileName):
        try:
            os.system("rm -rf %s" % self.fileName)
        except Exception as e:
            pass

    def connect(self, timeout=None):
        if 'telnet' in self.command:
            self.is_telnet_or_sol=CONECTION_TYPE_TELNET
        elif 'sol' in self.command:
            self.is_telnet_or_sol=CONECTION_TYPE_SOL
        else:
            raise Exception(f"Do not support type connect command {command}")
        
        self.handle = pexpect.spawn(
            self.command, encoding='utf-8', codec_errors='replace'
        )
        self.handle.maxread = 52428800
        self.handle.delaybeforesend = DELAY_BEFORE_SEND
        self.handle.timeout = TIMEOUT
    #    self.clear_buffer()
    #    return True 
    
    
        
    def _print_console(self, cmd):
        print (cmd)

    def disconnect(self, name_file, force_log=False):
        self.append_log(name_file)
        ret = True 
        if self.is_telnet_or_sol== CONECTION_TYPE_TELNET:
            ret = self.disconnect_telnet()
        elif  self.is_telnet_or_sol==CONECTION_TYPE_SOL :
            ret = self.disconnect_sol()
        if self.handle:
            self.process_logging(force_log=force_log)
            self.terminate()
        return ret

    def sendcontrol(self, char):
        if self.handle.delaybeforesend is not None:
            time.sleep(self.handle.delaybeforesend)
        self.handle.sendcontrol(char)

    def sendline(self, s=''):
        try:
            self.handle.delaybeforesend = None
            for char in s:
                self.handle.send(char)
                time.sleep(0.05)
            self.handle.send(LINE_SEPARATOR)
            self.handle.delaybeforesend = DELAY_BEFORE_SEND
        except Exception as err:
            self._print_error('Exception Error: %s' % str(err))
            return False
        return True
    def append_log(self, name_file):
        log_data=self.get_console_log()
        self.write_log(log_data)
        self.write_file(name_file,log_data)
        self.clear_buffer()
        
    def disconnect_telnet(self):
        self._print_console("Disconnecting")
        ret = 1
        # call
        try:
            # self.sendline("exit")
            # time.sleep(self.delay)
            self.sendline()
            time.sleep(self.delay)
            self.clear_buffer()
            self.sendcontrol(']')
            self.handle.expect('telnet>')
            self.sendline('quit')
            self.handle.expect('Connection close')
            self._print_console("Disconnected")
            ret = 0
        except (pexpect.TIMEOUT, pexpect.EOF):
            self._print_console("Unable to Disconnect")
        return ret
    def _print_error(self, cmd):
        print(cmd)
    def disconnect_sol(self):
        self._print_console("SOL Disconnect")
        ret = True
        cmd =self.command.replace('activate','deactivate')
        self._print_console(cmd)
        #if self.is_connected():
        try:
            self.sendline()
            time.sleep(self.delay)
            self.clear_buffer()
            os.system(cmd)
        except IOError:
            self._print_error("Unable to Disconnect")
            self.terminate()
        #else:
        #    self._print_console("Already Disconnected")
        #    ret, _ = os.system(cmd)
        return ret

    def process_logging(self, force_log=False):
        self._print_console("process_logging retry=%d" % self.retry)
        try:
            if self.retry == 0 or force_log:
                if self.handle.logfile:
                    self.handle.logfile.close()
                    self.handle.logfile = None
                    self.write_log(self.get_console_log())
        except IOError:
            self._print_error("Error on write file")

    def terminate(self):
        self.handle.terminate()
        self.handle.close()
        self.handle.kill(0)
        self.connected = 0

    def clear_buffer(self):
        output = ""
        expect_list = ['\w+\r\n', pexpect.TIMEOUT, pexpect.EOF]
        try:
            while 1:
                i = self.handle.expect(expect_list, timeout=2)
                if i == 0:
                    output = output + self.handle.before + self.handle.after
                else:
                    output = output + self.handle.before
                    break
        except Exception:
            pass
        expect_list = ['[\w+] \w+ ', pexpect.TIMEOUT, pexpect.EOF]
        try:
            while 1:
                i = self.handle.expect(expect_list, timeout=1)
                if i == 0:
                    output = output + self.handle.before + self.handle.after
                else:
                    output = output + self.handle.before
                    break
        except Exception:
            pass
        return output

    def clear_command(self):
        output = ""
        expect_list = ['\w+\r\n', pexpect.TIMEOUT, pexpect.EOF]
        try:
            i = self.handle.expect(expect_list, timeout=2)
            if i == 0:
                output = output + self.handle.before + self.handle.after
            else:
                output = output + self.handle.before
        except Exception:
            pass
        return output
        
    def get_console_log(self):
        output = ""
        expect_list = ['\w+\r\n', pexpect.TIMEOUT, pexpect.EOF]
        try:
            while 1:
                i = self.handle.expect(expect_list, timeout=2)
                if i == 0:
                    output = output + self.handle.before + self.handle.after
                else:
                    output = output + self.handle.before
                    break
        except Exception:
            pass
        #self._print_console(output)
        return output