import os; import re; import requests; import subprocess; import psutil; from pypresence import Presence; from typing import TextIO; import numpy as np; import websocket; import tls_client; import sys; from colorama import Fore, init, Style; import shutil; from threading import Thread, Lock, activeCount; import datetime; import json;import time; import websocket; import base64; import random; import string; lock = Lock(); 
sdir = os.path.dirname(os.path.abspath(__file__))
data = os.path.join(sdir, 'data')
if not os.path.exists(data):
    os.makedirs(data)
    with open(os.path.join(data, 'tokens.txt'), 'w') as f:
        f.write('')
    with open(os.path.join(data, 'proxies.txt'), 'w') as f:
        f.write('#HTTP-Proxies only.\nIf youre going to use proxies, delete this.')
configp = os.path.join(sdir, 'config.json')
if not os.path.exists(configp):
    with open(configp, 'w') as f:
        config = {"useProxies": False, "useRpc": True}
        json.dump(config, f)

with open(configp, 'r') as f:
    config = json.load(f)
useProxies = config.get('useProxies', False)
useRpc = config.get('useRpc', False)
class Colors:
    BLACK = (0, 0, 0)
    WHITE = (255, 255, 255)
    RED = (255, 0, 0)
    GREEN = (0, 255, 0)
    BLUE = (0, 0, 255)
    YELLOW = (255, 255, 0)
    MAGENTA = (255, 0, 255)
    CYAN = (0, 255, 255)



def gradient(start, end, text, r):
    start_r, start_g, start_b = start
    end_r, end_g, end_b = end
    ll = len(text)
    crange = [(int(start_r + (end_r - start_r) * i / ll),
                    int(start_g + (end_g - start_g) * i / ll),
                    int(start_b + (end_b - start_b) * i / ll))
                   for i in range(len(text))]
    output = ""
    for i, char in enumerate(text):
        output += f"\033[38;2;{crange[i][0]};{crange[i][1]};{crange[i][2]}m{char}"
    if r:
        output += "\033[0m"
        return(output)
    else:
        output += "\033[0m".center(os.get_terminal_size().columns)
        print(output)


def mfunc(modules_list):
    max_len = max(len(m) for m in modules_list)
    for i in range(len(modules_list)):
        modules_list[i] += [""] * (max_len - len(modules_list[i]))
    terminal_width = os.get_terminal_size().columns
    num_lists = len(modules_list)
    col_width = (terminal_width - num_lists - 1) // num_lists
    output = ""
    for i in range(max_len):
        line = "  ".join(m[i].ljust(col_width) for m in modules_list)
        left_padding = (terminal_width - len(line)) // 2
        output += (" " * left_padding) + line + "\n"
    return(output)


remtokens = []

os.system('cls')
os.system('title Heroine, The cheapest spammer.')


def rpc(id : str, am : int or float):
    try:
        richp = Presence(id)
        richp.connect()
        richp.update(large_text="Smoking heroine!",small_text="Heroine; the best raiding tool for 4.50$", details=f" . tokens : {am} .", state=f" . current date : {datetime.datetime.now().day}/{datetime.datetime.now().month}/{datetime.datetime.now().year} . ", large_image="rpc", buttons=[{"label":"server - ","url":"https://discord.gg/SWtTkvTK"}])
    except:
        pass


class Utilites:
    def __init__(self) -> None:
        self.stream = TextIO = sys.stdout
    def output(self, text : str) -> None:
        self.stream.write(f"{text}\n")
        self.stream.flush()
        
    def time(self):
        return f"{datetime.datetime.now().hour}:{datetime.datetime.now().minute}:{datetime.datetime.now().hour}"
    def info(self, text : str):
        time = self.time(); self.output(f"[{Fore.LIGHTBLUE_EX}{time}{Fore.RESET}]{Fore.RESET}{Fore.LIGHTBLUE_EX} [#] {Fore.LIGHTBLUE_EX}{text}{Fore.RESET}");
    def error(self, text : str):
        time = self.time(); self.output(f"[{Fore.LIGHTBLUE_EX}{time}{Fore.RESET}]{Fore.RESET}{Fore.LIGHTRED_EX} [!] {Fore.LIGHTRED_EX}{text}{Fore.RESET}");
    def worked(self, text : str):
        time = self.time(); self.output(f"[{Fore.LIGHTBLUE_EX}{time}{Fore.RESET}]{Fore.RESET}{Fore.LIGHTGREEN_EX} [*] {Fore.LIGHTGREEN_EX}{text}{Fore.RESET}");
    def random(self, leg : int):
        return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(leg))
    def removeFile(self, text, filen):
        with open(f"{filen}.txt", "r+") as f:
            lines = f.readlines()
        with open(f'{filen}.txt', "w") as f:
            for l in lines:
                if l.strip("\n") != text:
                    f.write(l)
                else:
                    pass
                f.truncate()



def getCookie(session):
    x = session.get("https://discord.com", headers={}).text
    return "; ".join(f"{k}={v}" for k,v in session.cookies.items())

class serverscrape:
    def __init__(self, token: str, id: str) -> None:
        self.token      = token
        self.id         = id
        self.baseurl    = f"https://discord.com/api/v9/guilds/{self.id}"
        self.session    = tls_client.Session(client_identifier='chrome_108')
        self.headers    = {"Authorization": self.token}

    def do_ruest(self, url) -> dict:
        return self.session.get(
            url     = url,
            headers = self.headers,
        ).json()

    def get_channels(self) -> dict:
        return self.do_ruest(f"{self.baseurl}/channels")

    def get_info(self) -> dict:
            return self.do_ruest(self.baseurl)

    def get_data(self) -> dict:
        info = self.get_info()
        return {
            "roles"     : info["roles"],
            "channels"  : self.get_channels(),
        }



class Utils:
    def rangeCorrector(ranges):
        if [0, 99] not in ranges:
            ranges.insert(0, [0, 99])
        return ranges

    def getRanges(index, multiplier, memberCount):
        initialNum = int(index*multiplier)
        rangesList = [[initialNum, initialNum+99]]
        if memberCount > initialNum+99:
            rangesList.append([initialNum+100, initialNum+199])
        return Utils.rangeCorrector(rangesList)

    def parseGuildMemberListUpdate(response):
        memberdata = {
            "online_count": response["d"]["online_count"],
            "member_count": response["d"]["member_count"],
            "id": response["d"]["id"],
            "guild_id": response["d"]["guild_id"],
            "hoisted_roles": response["d"]["groups"],
            "types": [],
            "locations": [],
            "updates": []
        }

        for chunk in response['d']['ops']:
            memberdata['types'].append(chunk['op'])
            if chunk['op'] in ('SYNC', 'INVALIDATE'):
                memberdata['locations'].append(chunk['range'])
                if chunk['op'] == 'SYNC':
                    memberdata['updates'].append(chunk['items'])
                else:  # invalidate
                    memberdata['updates'].append([])
            elif chunk['op'] in ('INSERT', 'UPDATE', 'DELETE'):
                memberdata['locations'].append(chunk['index'])
                if chunk['op'] == 'DELETE':
                    memberdata['updates'].append([])
                else:
                    memberdata['updates'].append(chunk['item'])

        return memberdata


class DiscordSocket(websocket.WebSocketApp):
    def __init__(self, token, guild_id, channel_id):
        self.token = token
        self.guild_id = guild_id
        self.channel_id = channel_id

        self.socket_headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"
        }

        super().__init__("wss://gateway.discord.gg/?encoding=json&v=9",
                         header=self.socket_headers,
                         on_open=lambda ws: self.sock_open(ws),
                         on_message=lambda ws, msg: self.sock_message(ws, msg),
                         on_close=lambda ws, close_code, close_msg: self.sock_close(
                             ws, close_code, close_msg)
                         )

        self.endScraping = False

        self.guilds = {}
        self.members = {}

        self.ranges = [[0, 0]]
        self.lastRange = 0
        self.packets_recv = 0

    def run(self):
        self.run_forever()
        return self.members

    def scrapeUsers(self):
        if self.endScraping == False:
            self.send('{"op":14,"d":{"guild_id":"' + self.guild_id +
                      '","typing":true,"activities":true,"threads":true,"channels":{"' + self.channel_id + '":' + json.dumps(self.ranges) + '}}}')

    def sock_open(self, ws):
        #print("[Gateway]", "Connected to WebSocket.")
        self.send('{"op":2,"d":{"token":"' + self.token + '","capabilities":125,"properties":{"os":"Windows","browser":"Firefox","device":"","system_locale":"it-IT","browser_user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0","browser_version":"94.0","os_version":"10","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":103981,"client_event_source":null},"presence":{"status":"online","since":0,"activities":[],"afk":false},"compress":false,"client_state":{"guild_hashes":{},"highest_last_message_id":"0","read_state_version":0,"user_guild_settings_version":-1,"user_settings_version":-1}}}')

    def heartbeatThread(self, interval):
        try:
            while True:
                #print("sending heartbeat")
                self.send('{"op":1,"d":' + str(self.packets_recv) + '}')
                time.sleep(interval)
        except Exception as e:
            pass  # print(e)
            return  # returns when socket is closed

    def sock_message(self, ws, message):
        decoded = json.loads(message)

        if decoded is None:
            return

        if decoded["op"] != 11:
            self.packets_recv += 1

        if decoded["op"] == 10:
            Thread(target=self.heartbeatThread, args=(
                decoded["d"]["heartbeat_interval"] / 1000, ), daemon=True).start()

        if decoded["t"] == "READY":
            for guild in decoded["d"]["guilds"]:
                self.guilds[guild["id"]] = {
                    "member_count": guild["member_count"]}

        if decoded["t"] == "READY_SUPPLEMENTAL":
            self.ranges = Utils.getRanges(
                0, 100, self.guilds[self.guild_id]["member_count"])
            #print(self.ranges)
            self.scrapeUsers()

        elif decoded["t"] == "GUILD_MEMBER_LIST_UPDATE":
            parsed = Utils.parseGuildMemberListUpdate(decoded)

            if parsed['guild_id'] == self.guild_id and ('SYNC' in parsed['types'] or 'UPDATE' in parsed['types']):
                for elem, index in enumerate(parsed["types"]):
                    if index == "SYNC":
                        # and parsed['locations'][elem] in self.ranges[1:]: #checks if theres nothing in the SYNC data
                        if len(parsed['updates'][elem]) == 0:
                            self.endScraping = True
                            break

                        for item in parsed["updates"][elem]:
                            if "member" in item:
                                mem = item["member"]
                                obj = {"tag": mem["user"]["username"] + "#" +
                                       mem["user"]["discriminator"], "id": mem["user"]["id"]}

                                self.members[mem["user"]["id"]] = obj
                                #print("<SYNC>", "synced", mem["user"]["id"])

                    elif index == "UPDATE":
                        for item in parsed["updates"][elem]:
                            if "member" in item:
                                mem = item["member"]
                                obj = {"tag": mem["user"]["username"] + "#" +
                                       mem["user"]["discriminator"], "id": mem["user"]["id"]}

                                self.members[mem["user"]["id"]] = obj
                                #print("<SYNC>", "synced", mem["user"]["id"]) # ah 1s

                    #print(self.endScraping)
                    #print(self.ranges)
                    #print("parsed", len(self.members))

                    self.lastRange += 1
                    self.ranges = Utils.getRanges(
                        self.lastRange, 100, self.guilds[self.guild_id]["member_count"])
                    time.sleep(0.35)
                    self.scrapeUsers()

            if self.endScraping:
                self.close()

    def sock_close(self, ws, close_code, close_msg):
        pass
        print("closed connection", close_code, close_msg)


def scrape(token, guild_id, channel_id):
    sb = DiscordSocket(token, guild_id, channel_id)
    return sb.run()

def dmspam():
    t = gradient(Colors.RED, Colors.MAGENTA, "Guild ID - ", True)
    g = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Channel ID - ", True)
    c = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "User ID - ", True)
    u = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Amount - ", True)
    amt = int(input(t))
    Trollery = DiscordTrollery()
    table = []
    tkns = open("data/tokens.txt", "r").read().splitlines()
    for x in tkns:
        t = Thread(target=Trollery.Dm, args=(x, g, c, u, amt))
        ta = Thread(target=table.append(t)).start()
    for x in table:
        x.start()
    for x in table:
        x.join()
    U = Utilites()
    U.worked(f'Finished.')

def get_js() -> str:
    try:
        e = tls_client.Session(client_identifier='chrome_108').get(f'https://discord.com/app')
        js_version = e.text.split('"></script><script src="/assets/')[2].split('" integrity')[0]
        req = tls_client.Session(client_identifier='chrome_108').get(f"https://discord.com/assets/{js_version}")
        build_number = req.text.split('(t="')[1].split('")?t:"")')[0]
        return build_number
    except Exception as e:
        Utils = Utilites()
        Utils.error(f'Failed to get latest build number {e}')

global buildNum; buildNum = get_js()
def buildxprop(num):
    return base64.b64encode(json.dumps({"os":"Windows","browser":"Discord Client","system_locale":"en-US","os_version":"10.0.19044","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":num,"client_event_source":None,"design_id":0}).encode()).decode()

def Boost():
    inv = ''
    t = gradient(Colors.RED, Colors.MAGENTA, "Guild ID - ", True)
    guild = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Join Before Boost - ", True)
    yes = input(t)
    if yes == 'y':
        t = gradient(Colors.RED, Colors.MAGENTA, "Invite Code - ", True)
        inv = input(t)
        yes = True 
    else:
        yes = False
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    Trollery = DiscordTrollery()
    table = []
    for x in tkns:
        t = Thread(target=Trollery.boost, args=(x, guild,yes, inv))
        ta = Thread(target=table.append(t)).start()
    for x in table:
        x.start()
    for x in table:
        x.join()
    U = Utilites()
    U.info(f'Boosted with tokens!')
    time.sleep(5)
    os.system('cls')
    structUi()


def Checker():
    table = []
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    DiscordTrolling = DiscordTrollery()
    for x in tkns:
        t = Thread(target=DiscordTrolling.checker, args=(x,))
        ta = Thread(target=table.append(t)).start()
    U = Utilites()
    for x in table:
        x.start()
    for x in table:
        x.join()
    U = Utilites()
    U.info(f'Finished checking tokens!')
    for x in remtokens:
        U = Utilites()
        U.removeFile(x, "data/tokens")   
    time.sleep(5)
    os.system('cls')
    structUi()

def Bio():
    i = ''
    t = gradient(Colors.RED, Colors.MAGENTA, "Bio - ", True)
    i = input(t)
    table = []
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    DiscordTrolling = DiscordTrollery()
    for x in tkns:
        t = Thread(target=DiscordTrolling.setBio, args=(x, i))
        ta = Thread(target=table.append(t)).start()
    U = Utilites()
    for x in table:
        x.start()
    for x in table:
        x.join()
    U = Utilites()
    U.info(f'Finished setting bio!')
    time.sleep(5)
    os.system('cls')
    structUi()

def Joiner():
    i = ''
    tin = gradient(Colors.RED, Colors.MAGENTA, "Invite Regex - ", True)
    i = input(tin)
    f = False
    table = []
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    DiscordTrolling = DiscordTrollery()
    content = DiscordTrolling.getXCont(i)
    for x in tkns:
        t = Thread(target=DiscordTrolling.joinServer, args=(x, i, f, content))
        ta = Thread(target=table.append(t)).start()
    U = Utilites()
    for x in table:
        x.start()
    for x in table:
        x.join()
    U = Utilites()
    U.info(f'Finished joining!')
    time.sleep(5)
    os.system('cls')
    structUi()

def thread():
    t = gradient(Colors.RED, Colors.MAGENTA, "Channel ID - ", True)
    c = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Thread Name - ", True)
    n = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Amount - ", True)
    a = int(input(t))
    table = []
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    DiscordTrolling = DiscordTrollery()
    for x in tkns:
        t = Thread(target=DiscordTrolling.threadSpam, args=(x, c, n, a))
        ta = Thread(target=table.append(t)).start()
    U = Utilites()
    for x in table:
        x.start()
    for x in table:
        x.join()
    U = Utilites()
    U.info(f'Finished spamming threads.')
    time.sleep(5)
    os.system('cls')
    structUi()

def Massfriend():
    table = []
    id = ''
    Tag = ''
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    Trolling = DiscordTrollery()
    t = gradient(Colors.RED, Colors.MAGENTA, "Mode [REMOVE/ADD] - ", True)
    i = input(t)
    if i == 'remove':
        t = gradient(Colors.RED, Colors.MAGENTA, "User ID - ", True)
        id = input(t)
        i = True 
    else:
        i = False
        t = gradient(Colors.RED, Colors.MAGENTA, "Tag - ", True)
        Tag = input(t)
    
    for x in tkns:
        t = Thread(target=Trolling.addUser, args=(x, Tag, id, i))
        ta = Thread(target=table.append(t)).start()
    for x in table:
        x.start()
    for x in table:
        x.join()
    U = Utilites()
    U.info(f'Finished adding user!')
    time.sleep(5)
    os.system('cls')
    structUi()

def Onliner():
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    table = []
    Trolling = DiscordTrollery()
    for x in tkns:
        t = Thread(target=Trolling.online, args=(x,))
        ta = Thread(target=table.append(t)).start()
    U = Utilites()
    for x in table:
        x.start()
    for x in table:
        x.join()
    U = Utilites()
    U.info(f'Finished onlining tokens!')
    time.sleep(5)
    os.system('cls')
    structUi()

global xprop; xprop = buildxprop(buildNum)
class DiscordTrollery:
    def __init__(self) -> None:
        self.session = tls_client.Session(client_identifier='chrome_108')
        self.headers = {'authority': 'discord.com', 'accept': '*/*', 'accept-language': 'pl-PL, pl;q=0.9','cache-control': 'no-cache','content-type': 'application/json','cookie': '__dcfduid=676e06b0565b11ed90f9d90136e0396b; __sdcfduid=676e06b1565b11ed90f9d90136e0396bc28dfd451bebab0345b0999e942886d8dfd7b90f193729042dd3b62e2b13812f; __cfruid=1cefec7e9c504b453c3f7111ebc4940c5a92dd08-1666918609; locale=en-US','origin': 'https://discord.com','pragma': 'no-cache','referer': 'https://discord.com/channels/@me','sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"', 'sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36', 'x-debug-options': 'bugReporterEnabled', 'x-discord-locale': 'en-US', 'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImZyLUZSIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEwNy4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTA3LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlcGVhc2VfY2hhbm5lcCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjE1NDc1MCwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0='}

    def getXCont(self, code):
        try:
            session = tls_client.Session(client_identifier="chrome_108")
            req = session.get(f'https://discord.com/api/v9/invites/{code}?inputValue=lie&with_counts=true&with_expiration=true').json()
            guild_id = req["guild"]["id"]
            channel_id = req["channel"]["id"]
            type = req["type"]
            return base64.b64encode(json.dumps({"location": "Join Guild", "location_guild_id": guild_id, "location_channel_id": channel_id, "location_channel_type": int(type)}).encode()).decode()
        except:
            return base64.b64encode(json.dumps({"location":"Invite Button Embed","location_guild_id":"null","location_channel_id":"null","location_channel_type":1,"location_message_id":"null"} ).encode()).decode()
    def setBio(self, token, trr):
        headers = self.headers 
        headers["authorization"] = token 
        req = self.session.patch(f'https://discord.com/api/v9/users/%40me/profile', headers=headers, json={"bio":trr})
        if req.status_code == 200:
            mtok = token[:len(token) - 39]
            U = Utilites(); U.worked(f'Set bio | {trr} | {mtok}')
        else:
            mtok = token[:len(token) - 39]
            U = Utilites(); U.error(f'Failed to set bio | {trr} | {mtok}')
    
    def gc(self, token, target, alt):
        headers = self.headers
        headers["authorization"] = token
        js = {"recipients": [target, alt]}
        proxies = open("data/proxies.txt").read().splitlines()
        prx = 'http://' + random.choice(proxies)
        req = self.session.post("https://discord.com/api/v9/users/@me/channels", headers=headers, json=js, proxy=prx) if useProxies else self.session.post("https://discord.com/api/v9/users/@me/channels", headers=headers, json=js)
        if req.status_code == 200:
            mtok = token[:len(token) - 39]
            U = Utilites(); U.worked(f'Made GC | {mtok} | {req.json()["id"]}');
        else:
            U = Utilites(); U.error(f'Failed to make GC | {mtok}')


    def Dm(self, token, guild, channel, user, amount):
        headers = self.headers
        headers["authorization"] = token
        headers["referer"] = f"https://discord.com/channels/{guild}/{channel}"
        headers["x-context-properties"] = "e30="
        mtok = token[:len(token) - 39]
        payload = {"recipients":[user]}
        for x in range(amount):
            proxies = open("data/proxies.txt").read().splitlines()
            prx = 'http://' + random.choice(proxies)
            req = self.session.post("https://discord.com/api/v9/users/@me/channels", headers=headers, proxy=prx, json=payload) if useProxies else self.session.post("https://discord.com/api/v9/users/@me/channels", headers=headers, json=payload)

            if req.status_code == 200:
                U = Utilites(); U.worked(f'Sent DM | {user} | {mtok}')
            else:
                U = Utilites(); U.error(f'Failed to send DM | {user} | {mtok}')
    def threadSpam(self, token, channel, name, amount):
        headers = self.headers
        headers["authorization"] = token
        for x in range(amount):
            proxies = open("data/proxies.txt").read().splitlines()
            prx = 'http://' + random.choice(proxies)
            req = self.session.post(f'https://discord.com/api/v9/channels/{channel}/threads', headers=headers, json={"auto_archive_duration":4320, "location": "Plus Button", "name": name, "type": 11}, proxy=prx) if useProxies else self.session.post(f'https://discord.com/api/v9/channels/{channel}/threads', headers=headers, json={"auto_archive_duration":4320, "location": "Plus Button", "name": name, "type": 11})
            mtok = token[:len(token) - 39]
            if req.status_code == 201:
                U = Utilites()
                U.worked(f'Made thread! | {mtok}')
            else:
                U = Utilites()
                U.error(f'Failed to make thread | {mtok}')

    def online(self, token):
        Utils = Utilites()
        gm = ["BTD6", "Youtube", "Crunchyroll", "Roblox", "Spotify", "Badlion Client", "Lunar Client", "Minecraft", "Tidal", "Apple Music", "Twitch", "Pandora", "Google Chrome", "Brave", "Microsoft Edge", "Apex Legends", "Fortnite", "Valorant", "Visual Studio Code", "Sublime Text", "PUBG", "Steam Workspace", "Blender"]
        Game = random.choice(gm)
        web = websocket.WebSocket()
        web.connect('wss://gateway.discord.gg/?v=8&encoding=json')
        js = json.loads(web.recv())
        auth = {"op": 2, "d":{"token": token, "properties": {"$os": f"{sys.platform}", "$browser": "RTB", "$device": f"{sys.platform} Device"},"presence": {"game": {"name": Game, "type": 0},"status":"dnd","since":0,"afk":False}},"s":None, "t":None}
        web.send(json.dumps(auth))
        ack={"op":1,"d":None}
        try:
            mtok = token[:len(token) - 39]
            Utils.worked(f'Onlined token! | {mtok}')
            web.send(json.dumps(ack))
        except Exception as e:
            Utils.error(f'Failed to online token! | {mtok}')
        
    def joinServer(self, token, invite, useOnline, xc):
        Utils = Utilites()
        Utils.info(f'Getting session..')
        try:
            ws = websocket.WebSocket()
            ws.connect("wss://gateway.discord.gg/?v=9&encoding=json"); ws.send(json.dumps({"op": 2,"d": {"token": token, "properties": {"$os": "windows","$browser": "Discord","$device": "desktop"},"presence": {"status": random.choice(["online", "dnd", "idle"]),"since": 0,"activities": [],"afk": False}}}))
        except:
            U = Utilites(); U.error(f'Failed to start websocket connection')
        for i in range(10):
            try:
                recv = json.loads(ws.recv())
                session = recv["d"]["session_id"]
                break 
            except:
                pass 
        Utils.worked(f'Got Session | {session}')
        mtok = token[:len(token) - 39]
        proxies = open("data/proxies.txt").read().splitlines()
        prx = 'http://' + random.choice(proxies)
        headers = self.headers
        headers["authorization"] = token
        headers["x-content-properties"] = xc
        try:
            req = self.session.post(f'https://discord.com/api/v9/invites/{invite}', headers=headers, json={"session_id": session}, proxy=prx) if useProxies else self.session.post(f'https://discord.com/api/v9/invites/{invite}', headers=headers, json={"session_id": session}) 
            if req.status_code == 200:
                Utils.worked(f'Joined server | {invite} | {mtok}')
                if useOnline:
                    self.online(token)
            else:
                Utils.error(f'Failed to join server, Api banned? | {invite} | {mtok}')
        except:
            U = Utilites(); U.error(f'Failed to send request.')

    
    def checker(self, token):
        headers = self.headers
        headers["authorization"] = token
        proxies = open("data/proxies.txt").read().splitlines()
        prx = 'http://' + random.choice(proxies)
        U = Utilites()
        mtoken = token[:len(token) - 39]
        req = self.session.get("https://discord.com/api/v9/users/@me/affinities/guilds", headers={"authorization": token}, proxy=prx) if useProxies else self.session.get("https://discord.com/api/v9/users/@me", headers={"authorization": token})
        if req.status_code == 200:
            U.worked(f'Valid token | {mtoken}')
        elif req.status_code == 401:
            U = Utilites()
            U.error(f'Invalid token | {token}')
            remtokens.append(token)
        elif req.status_code == 403:
            U = Utilites()
            U.error(f'Locked token | {token}')
            remtokens.append(token)
        else:
            U = Utilites()
            U.error(f'Invalid token | {token}')
            remtokens.append(token)
    def addUser(self, token, tag, id, unadd):
        if unadd:
            Utils = Utilites()
            headers = self.headers
            headers["authorization"] = token
            headers["x-context-properties"] = "eyJsb2NhdGlvbiI6IkFkZCBGcmllbmQifQ=="
            proxies = open("data/proxies.txt").read().splitlines()
            prx = 'http://' + random.choice(proxies)
            req = self.session.delete(f"https://discord.com/api/v9/users/@me/relationships/{id}", headers=headers, json={}, proxy=prx) if useProxies else self.session.delete(f"https://discord.com/api/v9/users/@me/relationships/{id}", headers=headers, json={})
            if req.status_code == 204:
                Utils.worked(f'Unadded | {id}!')
            else:
                Utils.error(f'Failed to unadd | {id}!')
        else:
            headers = self.headers
            headers["authorization"] = token
            headers["x-context-properties"] = "eyJsb2NhdGlvbiI6IkFkZCBGcmllbmQifQ=="
            username, discriminator = tag.split("#")
            proxies = open("data/proxies.txt").read().splitlines()
            prx = 'http://' + random.choice(proxies)
            req = self.session.post(f'https://discord.com/api/v9/users/@me/relationships', headers=headers, json={"username":username, "discriminator":discriminator}, proxy=prx) if useProxies else self.session.post(f'https://discord.com/api/v9/users/@me/relationships', headers=headers, json={"username":username, "discriminator":discriminator})
            Utils = Utilites()
            mtok = token[:len(token) - 39]
            if req.status_code == 204:
                Utils.worked(f'Added | {tag} | {mtok}')
            else:
                Utils.error(f'Failed to add | {tag} | {mtok}')
    
    def react(self, token, channelid, messageid, emoji):
        headers = self.headers
        headers["authorization"] = token
        proxies = open("data/proxies.txt").read().splitlines()
        prx = 'http://' + random.choice(proxies)
        mtok = token[:len(token) - 39]
        req = self.session.put(f'https://discord.com/api/v9/channels/{channelid}/messages/{messageid}/reactions/{emoji}/%40me?location=Message&type=0',headers=headers, json={'location': 'Message', 'type': 0}, proxy=prx) if useProxies else self.session.put(f'https://discord.com/api/v9/channels/{channelid}/messages/{messageid}/reactions/{emoji}/%40me?location=Message&type=0',headers=headers, json={'location': 'Message', 'type': 0})
        if req.status_code == 204: U = Utilites(); U.worked(f'Reacted to message | {messageid} | {mtok}');
        else: U = Utilites(); U.error(f'Failed to react | {mtok}')
    def boost(self, token, guildid, join, inv):
        if join:
            xContent = self.getXCont(inv)
            self.joinServer(token, inv, True)
        headers = self.headers
        headers["authorization"] = token
        ids = []
        proxies = open("data/proxies.txt").read().splitlines()
        prx = 'http://' + random.choice(proxies)
        get = self.session.get("https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots", headers=headers, proxy=prx) if useProxies else self.session.get("https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots", headers=headers)
        try:
            for id in get.json():
                ids.append(id["id"])
            if ids != []:
                for i in range(len(ids)):
                    proxies = open("data/proxies.txt").read().splitlines()
                    prx = 'http://' + random.choice(proxies)
                    mtok = token[:len(token) - 39]
                    req = self.session.put(f'https://discord.com/api/v9/guilds/{guildid}/premium/subscriptions', headers=headers, json={"user_premium_guild_subscription_slot_ids": [f'{ids[i]}']}, proxy=prx) if useProxies else self.session.put(f'https://discord.com/api/v9/guilds/{guildid}/premium/subscriptions', headers=headers, json={"user_premium_guild_subscription_slot_ids": [f'{ids[i]}']})
                    if req.status_code == 201:
                        U = Utilites()
                        U.worked(f'Boosted {i+1} of {len(ids)} | {mtok}')
                    elif req.status_code == 400:
                        U = Utilites()
                        U.error(f'Boost already used {i+1} of {len(ids)} | {mtok}')
                    else:
                        U = Utilites()
                        U.error(f'Failed to boost server. | {mtok}')
                ids.clear()
            else:
                U = Utilites()
                U.error(f'No nitro found on tokens.')
        except:
            U = Utilites()
            U.error(f'Error.')

    def Spamma(self, massping, channels, message, ids, token, pings, amt):
        try:
            mems = []
            for u in ids:
                mems.append(f"<@{u}>")
            modl = message
            for x in range(amt):
                headers = self.headers
                headers['authorization'] = token
                if massping:
                    m = modl
                    t =''
                    for i in range(pings):
                        t = t + random.choice(mems)
                    m = m + ' - ' + t
                else:
                    m = message
                ch = random.choice(channels)
                proxies = open("data/proxies.txt").read().splitlines()
                prx = 'http://' + random.choice(proxies)
                mtok = token[:len(token) - 39]
                req = self.session.post(f'https://discord.com/api/v9/channels/{ch}/messages', headers=headers, json={"content": m, "tts":False}, proxy=prx) if useProxies else self.session.post(f'https://discord.com/api/v9/channels/{ch}/messages', headers=headers, json={"content": m, "tts":False})
                if req.status_code == 200:
                    u = Utilites()
                    u.worked(f'Sent message | {modl} | {mtok}')
                else:
                    u = Utilites()
                    u.error(f'Failed to send message | {modl} | {mtok}')
        except Exception as e:
            U = Utilites()
            U.error(f'Failed to send request. {e}')



def gcSpam():
    e = DiscordTrollery()
    stoken = ""
    ftoken = ""
    etoken = ""
    t = gradient(Colors.RED, Colors.MAGENTA, "Token - ", True)
    ftoken = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Target ID - ", True)
    stoken = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Alt ID - ", True)
    etoken = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Amount - ", True)
    amount = int(input(t))
    tab = []
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    for x in range(amount):
        t = Thread(target=e.gc, args=(ftoken, stoken, etoken))
        tab.append(t)
    for x in tab:
        x.start()
    for x in tab:
        x.join()
        U = Utilites(); U.info(f'Finished spamming gcs!'); time.sleep(4); os.system('cls'); structUi()
def Reactor():
    e = DiscordTrollery()
    emoji_id = ""
    message_id = ""
    channel_id = ""
    t = gradient(Colors.RED, Colors.MAGENTA, "Channel ID - ", True)
    channel_id = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Message ID - ", True)
    message_id = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Paste Emoiji - ", True)
    emoji_id = input(t)
    tab = []
    tkns = open("data/tokens.txt", "r+").read().splitlines()
    for x in tkns:
        t = Thread(target=e.react, args=(x, channel_id, message_id, emoji_id))
        tab.append(t)
    for x in tab:
        x.start()
    for x in tab:
        x.join()
    U = Utilites(); U.info(f'Finished reacting!'); time.sleep(4); os.system('cls'); structUi()
def Spammer():
    e = DiscordTrollery()
    ids = []
    eee = 0
    scrapech = ''
    tucan = ''
    guild = ''
    message = ''
    ppm = 0
    t = gradient(Colors.RED, Colors.MAGENTA, "MassPing [Y/N] - ", True)
    idc = input(t)
    t = gradient(Colors.RED, Colors.MAGENTA, "Channel IDS - ", True)
    channel = input(t)
    channels = re.split(',|, ', channel)
    t = gradient(Colors.RED, Colors.MAGENTA, "Messages Per Token - ", True)
    eee = int(input(t))
    t = gradient(Colors.RED, Colors.MAGENTA, "Message - ", True)
    message = input(t)
    if idc == 'y':
        t = gradient(Colors.RED, Colors.MAGENTA, "Guild ID - ", True)
        guild = input(t)
        t = gradient(Colors.RED, Colors.MAGENTA, "Token - ", True)
        tucan = input(t)
        t = gradient(Colors.RED, Colors.MAGENTA, "Scrape Channel - ", True)
        scrapech = input(t)
        t = gradient(Colors.RED, Colors.MAGENTA, "Pings Per MSG - ", True)
        ppm = int(input(t))
        ids = scrape(tucan, guild, scrapech)
        U = Utilites()
        U.info(f'Scraped {len(ids)}!')
        idc = True 
    else:
        idc = False 
    

    tk = open("data/tokens.txt", "r+").read().splitlines()
    tbl = []
    for x in tk:
        t = Thread(target=e.Spamma, args=(idc,channels,message,ids, x, ppm, eee))
        tbl.append(t)
    for x in tbl:
        x.start()
    for x in tbl:
        x.join()

    U = Utilites()
    U.info(f'Finished spamming.')
    time.sleep(5)
    os.system('cls')
    structUi()

class UI:
    def __init__(self) -> None:
        pass 
    def centerText(self, text : str):
        le = len(text)
        width = os.get_terminal_size().columns
        idkdrakonwrotethisandicopiedit = " " * round((int(width) - (le + 5))/2)
        s = idkdrakonwrotethisandicopiedit + text 
        return s
U = UI()
asd = "  _  _ ____ _____  __   (_)  _  _  ____".center(os.get_terminal_size().columns)
i1 = " | || ||___ |  _| /  \   _  | \| | |____".center(os.get_terminal_size().columns)
i2 = " |====||___ | \  |    | | | |    | |____".center(os.get_terminal_size().columns)
i3 = "|_||_|\___ |__\  \__/  |_| |_|\_| \___".center(os.get_terminal_size().columns)



def structUi() -> None:
    import webbrowser
    url = "https://discord.gg/cNhU5bqy"
    webbrowser.open(url)
    classUi = UI()
    e = Fore.LIGHTCYAN_EX
    w = Fore.LIGHTCYAN_EX
    M1 = ["    [1] - Joiner", "    [2] - Spammer", "    [3] - Onliner", "    [4] - Booster"]
    M2 = ["[5] - Mass Friend", "[6] - Reactor", "[7] - Token Checker", "[8] - Thread Spammer"]
    M3 = ["[9] - Group Spammer", "[10] - DM Spammer", "[11] - Mass Bio"]
    main = [M1, M2, M3]
    asd = "  _  _ ____ _____  __   (_)  _  _   ____".center(os.get_terminal_size().columns)
    i1 = " | || ||___ |  _| /  \   _  | \| | |____".center(os.get_terminal_size().columns)
    i2 = " |====||___ | \  |    | | | |    | |____".center(os.get_terminal_size().columns)
    i3 = "|_||_|\___ |__\  \__/  |_| |_|\_| \___".center(os.get_terminal_size().columns)
    output = mfunc(main)

    gradient(Colors.RED, Colors.MAGENTA, f'{asd}{i1}{i2}{i3}', False)
    gradient(Colors.RED, Colors.MAGENTA, output, False)
    tucans = open("data/tokens.txt").read().splitlines()
    prx = open("data/proxies.txt").read().splitlines()
    p = 0
    for i in prx:
        if i.isnumeric() or ':' in i:
            p += 1
    if useRpc:
        print("")
    else:
        pass
    text = f"Loaded {len(tucans)} tokens and {p} proxies".center(os.get_terminal_size().columns-13+len(M1))
    gradient(Colors.MAGENTA, Colors.CYAN, text, False)
    t = "-> "
    
    e = gradient(Colors.MAGENTA, Colors.CYAN, t, True)
    i = input(e)


    if i == "1":
        Joiner()
    elif i == "2":
        Spammer()
    elif i == "3":
        Onliner()
    elif i == "4":
        Boost()
    elif i == "5":
        Massfriend()
    elif i == "6":
        Reactor()
    elif i == "7":
        Checker()
    elif i == "8":
        thread()
    elif i == "9":
        gcSpam()
    elif i == "10":
        dmspam()
    elif i == "11":
        Bio()
    else:
        U = Utilites()
        U.error('Invalid option.. going back to UI.')
        time.sleep(2)
        os.system('cls')
        structUi()

structUi()
